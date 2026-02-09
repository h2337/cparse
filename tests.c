#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clex/clex.h"
#include "cparse.h"
#include "grammar.h"
#include "lr1_lalr1.h"

static int failures = 0;

#define EXPECT_TRUE(cond, msg)                                        \
  do {                                                                \
    if (!(cond)) {                                                    \
      fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, msg); \
      failures++;                                                     \
    }                                                                 \
  } while (0)

#define EXPECT_STREQ(actual, expected, msg)                           \
  do {                                                                \
    if (strcmp((actual), (expected)) != 0) {                          \
      fprintf(stderr, "[FAIL] %s:%d: %s (got '%s', expected '%s')\n", \
              __FILE__, __LINE__, msg, (actual), (expected));         \
      failures++;                                                     \
    }                                                                 \
  } while (0)

#define EXPECT_STATUS(actual, expected, msg)                             \
  do {                                                                   \
    cparseStatus _actual = (actual);                                     \
    cparseStatus _expected = (expected);                                 \
    if (_actual != _expected) {                                          \
      fprintf(stderr, "[FAIL] %s:%d: %s (got status %d, expected %d)\n", \
              __FILE__, __LINE__, msg, (int)_actual, (int)_expected);    \
      failures++;                                                        \
    }                                                                    \
  } while (0)

typedef struct {
  const char* pattern;
  int kind;
  const char* label;
} TokenSpec;

static bool set_contains(const SymbolSet* set, const char* key,
                         const char* value) {
  const SymbolSetEntry* entry = symbol_set_find_const(set, key);
  if (!entry) {
    return false;
  }
  return string_vec_contains(&entry->values, value);
}

static void test_first_follow(void) {
  const char* src = "S -> A A\nA -> a A | b\nB -> epsilon";
  Grammar* grammar = cparseGrammar(src);
  EXPECT_TRUE(grammar != NULL, "cparseGrammar returned NULL");
  EXPECT_STREQ(grammar->start, "S", "start symbol mismatch");
  EXPECT_TRUE(string_vec_contains(&grammar->terminals, "a"),
              "missing terminal a");
  EXPECT_TRUE(string_vec_contains(&grammar->terminals, "b"),
              "missing terminal b");
  EXPECT_TRUE(set_contains(&grammar->first, "A", "a"), "FIRST(A) missing a");
  EXPECT_TRUE(set_contains(&grammar->first, "A", "b"), "FIRST(A) missing b");
  EXPECT_TRUE(set_contains(&grammar->follow, "A", "b"), "FOLLOW(A) missing b");
  EXPECT_TRUE(set_contains(&grammar->follow, "A", "$"), "FOLLOW(A) missing $");
  EXPECT_TRUE(set_contains(&grammar->first, "B", CPARSE_EPSILON),
              "FIRST(B) missing epsilon");
  cparseFreeGrammar(grammar);
}

static clexLexer* create_lexer(const TokenSpec* specs, size_t count) {
  clexLexer* lexer = clexInit();
  EXPECT_TRUE(lexer != NULL, "failed to initialise clex lexer");
  if (!lexer) {
    return NULL;
  }
  for (size_t i = 0; i < count; ++i) {
    if (!specs[i].pattern) {
      continue;
    }
    clexStatus status =
        clexRegisterKind(lexer, specs[i].pattern, specs[i].kind);
    char buffer[128];
    snprintf(buffer, sizeof(buffer), "failed to register token pattern %s",
             specs[i].label);
    EXPECT_TRUE(status == CLEX_STATUS_OK, buffer);
    if (status != CLEX_STATUS_OK) {
      clexLexerDestroy(lexer);
      return NULL;
    }
  }
  return lexer;
}

static bool parser_accepts(LR1Parser* parser, const char* input) {
  return cparseAccept(parser, input) == CPARSE_STATUS_OK;
}

static ParseTreeNode* parser_parse_tree(LR1Parser* parser, const char* input) {
  ParseTreeNode* tree = NULL;
  cparseStatus status = cparse(parser, input, &tree);
  if (status != CPARSE_STATUS_OK) {
    cparseFreeParseTree(tree);
    return NULL;
  }
  return tree;
}

static clexLexer* create_basic_lexer(void) {
  static const TokenSpec specs[] = {
      {"int", 0, "INT"},
      {"return", 1, "RETURN"},
      {"[a-zA-Z_]([a-zA-Z_]|[0-9])*", 2, "IDENTIFIER"},
      {";", 3, "SEMICOL"},
  };
  return create_lexer(specs, sizeof(specs) / sizeof(specs[0]));
}

static void test_lr1_accept_and_tree(void) {
  clexLexer* lexer = create_basic_lexer();
  if (!lexer) {
    return;
  }
  const char* grammar_src = "S -> A IDENTIFIER SEMICOL\nA -> RETURN";
  Grammar* grammar = cparseGrammar(grammar_src);
  EXPECT_TRUE(grammar != NULL, "failed to parse grammar");
  if (!grammar) {
    clexLexerDestroy(lexer);
    return;
  }
  const char* token_names[] = {"INT", "RETURN", "IDENTIFIER", "SEMICOL"};
  LR1Parser* parser =
      cparseCreateLR1Parser(grammar, lexer, token_names,
                            sizeof(token_names) / sizeof(token_names[0]));
  EXPECT_TRUE(parser != NULL, "failed to build LR(1) parser");
  if (!parser) {
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return;
  }
  EXPECT_TRUE(parser_accepts(parser, "return foo;"),
              "expected parser to accept valid input");
  EXPECT_TRUE(!parser_accepts(parser, "return"),
              "parser accepted invalid input");
  ParseTreeNode* tree = parser_parse_tree(parser, "return foo;");
  EXPECT_TRUE(tree != NULL, "parse tree is NULL");
  if (tree) {
    EXPECT_STREQ(tree->value, "S", "root value mismatch");
    EXPECT_TRUE(tree->children.size == 3, "S should have three children");
  }
  cparseFreeParseTree(tree);
  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
}

static void test_parse_tree_terminals(void) {
  clexLexer* lexer = create_basic_lexer();
  if (!lexer) {
    return;
  }
  const char* grammar_src = "S -> A IDENTIFIER SEMICOL\nA -> RETURN";
  Grammar* grammar = cparseGrammar(grammar_src);
  if (!grammar) {
    clexLexerDestroy(lexer);
    return;
  }
  const char* token_names[] = {"INT", "RETURN", "IDENTIFIER", "SEMICOL"};
  LR1Parser* parser =
      cparseCreateLR1Parser(grammar, lexer, token_names,
                            sizeof(token_names) / sizeof(token_names[0]));
  if (!parser) {
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return;
  }
  ParseTreeNode* tree = parser_parse_tree(parser, "return result;");
  EXPECT_TRUE(tree != NULL, "expected parse tree for valid input");
  if (tree && tree->children.size == 3) {
    ParseTreeNode* node_a = tree->children.items[0];
    ParseTreeNode* ident = tree->children.items[1];
    ParseTreeNode* semi = tree->children.items[2];
    EXPECT_TRUE(tree->span.start.line == 1, "tree start line mismatch");
    EXPECT_TRUE(tree->span.start.column == 1, "tree start column mismatch");
    EXPECT_TRUE(tree->span.end.line == 1, "tree end line mismatch");
    EXPECT_TRUE(tree->span.end.column == 15, "tree end column mismatch");
    EXPECT_STREQ(node_a->value, "A", "first child should be nonterminal A");
    EXPECT_TRUE(node_a->children.size == 1,
                "A should expand to a single RETURN token");
    if (node_a->children.size == 1) {
      ParseTreeNode* return_tok = node_a->children.items[0];
      EXPECT_STREQ(return_tok->value, "RETURN", "terminal mismatch for RETURN");
      EXPECT_STREQ(return_tok->token.lexeme, "return",
                   "RETURN lexeme mismatch");
      EXPECT_TRUE(return_tok->token.span.start.offset == 0,
                  "RETURN start offset mismatch");
      EXPECT_TRUE(return_tok->token.span.start.column == 1,
                  "RETURN start column mismatch");
    }
    EXPECT_STREQ(ident->value, "IDENTIFIER", "identifier node name mismatch");
    EXPECT_STREQ(ident->token.lexeme, "result", "IDENTIFIER lexeme mismatch");
    EXPECT_TRUE(ident->token.span.start.offset == 7,
                "IDENTIFIER start offset mismatch");
    EXPECT_TRUE(ident->token.span.start.column == 8,
                "IDENTIFIER start column mismatch");
    EXPECT_STREQ(semi->value, "SEMICOL", "semicolon node name mismatch");
    EXPECT_STREQ(semi->token.lexeme, ";", "semicolon lexeme mismatch");
    EXPECT_TRUE(semi->token.span.start.offset == 13,
                "SEMICOL start offset mismatch");
    EXPECT_TRUE(semi->token.span.start.column == 14,
                "SEMICOL start column mismatch");
  }
  cparseFreeParseTree(tree);
  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
}

static void test_lalr_accept(void) {
  clexLexer* lexer = create_basic_lexer();
  if (!lexer) {
    return;
  }
  const char* grammar_src = "S -> A IDENTIFIER SEMICOL\nA -> RETURN";
  Grammar* grammar = cparseGrammar(grammar_src);
  EXPECT_TRUE(grammar != NULL, "failed to parse grammar for LALR test");
  if (!grammar) {
    clexLexerDestroy(lexer);
    return;
  }
  const char* token_names[] = {"INT", "RETURN", "IDENTIFIER", "SEMICOL"};
  LALR1Parser* parser =
      cparseCreateLALR1Parser(grammar, lexer, token_names,
                              sizeof(token_names) / sizeof(token_names[0]));
  EXPECT_TRUE(parser != NULL, "failed to build LALR(1) parser");
  if (!parser) {
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return;
  }
  EXPECT_TRUE(parser_accepts(parser, "return bar;"),
              "LALR parser rejected valid input");
  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
}

static void test_indexed_parser_tables(void) {
  clexLexer* lexer = create_basic_lexer();
  if (!lexer) {
    return;
  }
  const char* grammar_src = "S -> A IDENTIFIER SEMICOL\nA -> RETURN";
  Grammar* grammar = cparseGrammar(grammar_src);
  if (!grammar) {
    clexLexerDestroy(lexer);
    return;
  }
  const char* token_names[] = {"INT", "RETURN", "IDENTIFIER", "SEMICOL"};
  LR1Parser* parser =
      cparseCreateLR1Parser(grammar, lexer, token_names,
                            sizeof(token_names) / sizeof(token_names[0]));
  EXPECT_TRUE(parser != NULL, "failed to build parser for table layout test");
  if (!parser) {
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return;
  }

  EXPECT_TRUE(parser->state_count == parser->collection.size,
              "state_count should match LR collection size");
  EXPECT_TRUE(parser->terminal_count >= grammar->terminals.size + 1,
              "terminal_count should include grammar terminals and EOF");
  EXPECT_TRUE(parser->nonterminal_count == grammar->nonterminals.size,
              "nonterminal_count should match grammar nonterminal count");
  EXPECT_TRUE(parser->action_table != NULL, "action table should be allocated");
  EXPECT_TRUE(parser->action_present != NULL,
              "action presence bitmap should be allocated");
  EXPECT_TRUE(parser->goto_table != NULL, "goto table should be allocated");
  EXPECT_TRUE(parser->token_kind_to_terminal != NULL,
              "token-kind to terminal map should be allocated");
  EXPECT_TRUE(parser->token_kind_to_terminal[0] >= 0,
              "unused lexer tokens should still map to terminal IDs");
  EXPECT_TRUE(parser->token_kind_to_terminal[1] >= 0,
              "RETURN should map to a terminal ID");
  EXPECT_TRUE(parser->token_kind_to_terminal[2] >= 0,
              "IDENTIFIER should map to a terminal ID");
  EXPECT_TRUE(parser->token_kind_to_terminal[3] >= 0,
              "SEMICOL should map to a terminal ID");

  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
}

static void test_parser_rejects_invalid_input(void) {
  clexLexer* lexer = create_basic_lexer();
  if (!lexer) {
    return;
  }
  const char* grammar_src = "S -> A IDENTIFIER SEMICOL\nA -> RETURN";
  Grammar* grammar = cparseGrammar(grammar_src);
  if (!grammar) {
    clexLexerDestroy(lexer);
    return;
  }
  const char* token_names[] = {"INT", "RETURN", "IDENTIFIER", "SEMICOL"};
  LR1Parser* parser =
      cparseCreateLR1Parser(grammar, lexer, token_names,
                            sizeof(token_names) / sizeof(token_names[0]));
  if (!parser) {
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return;
  }
  cparseStatus status = cparseAccept(parser, "return ;");
  EXPECT_STATUS(status, CPARSE_STATUS_UNEXPECTED_TOKEN,
                "malformed input should produce unexpected-token status");
  const cparseError* error = cparseGetLastError(parser);
  EXPECT_TRUE(error != NULL, "missing parser error for malformed input");
  if (error) {
    EXPECT_TRUE(error->position.line == 1, "unexpected error line");
    EXPECT_TRUE(error->position.column == 8, "unexpected error column");
    EXPECT_STREQ(error->offending_lexeme, ";", "offending lexeme mismatch");
    EXPECT_TRUE(error->expected_tokens.size > 0, "expected token set is empty");
  }
  ParseTreeNode* tree = NULL;
  status = cparse(parser, "return ;", &tree);
  EXPECT_STATUS(status, CPARSE_STATUS_UNEXPECTED_TOKEN,
                "cparse() should fail with unexpected token");
  EXPECT_TRUE(tree == NULL,
              "cparse should not return a tree for malformed input");
  cparseFreeParseTree(tree);
  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
}

static void test_parser_rejects_lexical_errors(void) {
  clexLexer* lexer = create_basic_lexer();
  if (!lexer) {
    return;
  }
  const char* grammar_src = "S -> IDENTIFIER";
  Grammar* grammar = cparseGrammar(grammar_src);
  if (!grammar) {
    clexLexerDestroy(lexer);
    return;
  }
  const char* token_names[] = {"INT", "RETURN", "IDENTIFIER", "SEMICOL"};
  LR1Parser* parser =
      cparseCreateLR1Parser(grammar, lexer, token_names,
                            sizeof(token_names) / sizeof(token_names[0]));
  if (!parser) {
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return;
  }
  EXPECT_TRUE(parser_accepts(parser, "value"),
              "parser rejected valid identifier");
  cparseStatus status = cparseAccept(parser, "value$tail");
  EXPECT_STATUS(status, CPARSE_STATUS_LEXICAL_ERROR,
                "lexical failure should bubble up as lexer error");
  const cparseError* error = cparseGetLastError(parser);
  EXPECT_TRUE(error != NULL, "missing parser error for lexical failure");
  if (error) {
    EXPECT_TRUE(error->position.line == 1, "lexer error line mismatch");
    EXPECT_TRUE(error->position.column == 6, "lexer error column mismatch");
    EXPECT_STREQ(error->offending_lexeme, "$",
                 "lexer offending lexeme mismatch");
    EXPECT_TRUE(error->expected_tokens.size > 0, "expected token set is empty");
  }
  ParseTreeNode* tree = NULL;
  status = cparse(parser, "value$tail", &tree);
  EXPECT_STATUS(status, CPARSE_STATUS_LEXICAL_ERROR,
                "cparse() should fail on lexical error");
  EXPECT_TRUE(
      tree == NULL,
      "cparse should not return a tree when lexical errors are present");
  cparseFreeParseTree(tree);
  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
}

static void test_conflicting_grammar_is_rejected(void) {
  enum {
    TOK_ID,
    TOK_PLUS,
  };
  static const TokenSpec specs[] = {
      {"[a-zA-Z_]([a-zA-Z_]|[0-9])*", TOK_ID, "ID"},
      {"\\+", TOK_PLUS, "PLUS"},
  };
  clexLexer* lexer = create_lexer(specs, sizeof(specs) / sizeof(specs[0]));
  if (!lexer) {
    return;
  }
  Grammar* grammar = cparseGrammar("E -> E PLUS E\nE -> ID");
  if (!grammar) {
    clexLexerDestroy(lexer);
    return;
  }
  const char* token_names[] = {"ID", "PLUS"};
  LR1Parser* parser =
      cparseCreateLR1Parser(grammar, lexer, token_names,
                            sizeof(token_names) / sizeof(token_names[0]));
  EXPECT_TRUE(parser == NULL,
              "conflicting grammar should fail parser creation");
  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
}

static void test_epsilon_grammar(void) {
  clexLexer* lexer = clexInit();
  EXPECT_TRUE(lexer != NULL, "failed to allocate lexer for epsilon grammar");
  const char* grammar_src = "S -> epsilon";
  Grammar* grammar = cparseGrammar(grammar_src);
  EXPECT_TRUE(grammar != NULL, "failed to build epsilon grammar");
  if (!grammar) {
    clexLexerDestroy(lexer);
    return;
  }
  LR1Parser* parser = cparseCreateLR1Parser(grammar, lexer, NULL, 0);
  EXPECT_TRUE(parser != NULL, "failed to build parser for epsilon grammar");
  if (!parser) {
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return;
  }
  EXPECT_TRUE(parser_accepts(parser, ""),
              "epsilon grammar should accept empty string");
  ParseTreeNode* tree = parser_parse_tree(parser, "");
  EXPECT_TRUE(tree != NULL, "parse tree should be produced for empty input");
  if (tree) {
    EXPECT_STREQ(tree->value, "S", "epsilon grammar root mismatch");
    EXPECT_TRUE(tree->children.size == 0,
                "epsilon grammar should have no children");
  }
  cparseFreeParseTree(tree);
  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
}

static void test_expression_grammar(void) {
  enum {
    TOK_NUMBER,
    TOK_PLUS,
    TOK_STAR,
    TOK_LPAREN,
    TOK_RPAREN,
  };
  static const TokenSpec expr_specs[] = {
      {"[0-9]+", TOK_NUMBER, "NUMBER"}, {"\\+", TOK_PLUS, "PLUS"},
      {"\\*", TOK_STAR, "STAR"},        {"\\(", TOK_LPAREN, "LPAREN"},
      {"\\)", TOK_RPAREN, "RPAREN"},
  };
  clexLexer* lexer =
      create_lexer(expr_specs, sizeof(expr_specs) / sizeof(expr_specs[0]));
  if (!lexer) {
    return;
  }
  const char* grammar_src =
      "Expr -> Term ExprTail\n"
      "ExprTail -> PLUS Term ExprTail | epsilon\n"
      "Term -> Factor TermTail\n"
      "TermTail -> STAR Factor TermTail | epsilon\n"
      "Factor -> NUMBER | LPAREN Expr RPAREN";
  Grammar* grammar = cparseGrammar(grammar_src);
  EXPECT_TRUE(grammar != NULL, "failed to parse expression grammar");
  if (!grammar) {
    clexLexerDestroy(lexer);
    return;
  }
  const char* token_names[] = {"NUMBER", "PLUS", "STAR", "LPAREN", "RPAREN"};
  LALR1Parser* parser =
      cparseCreateLALR1Parser(grammar, lexer, token_names,
                              sizeof(token_names) / sizeof(token_names[0]));
  EXPECT_TRUE(parser != NULL, "failed to build expression parser");
  if (!parser) {
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return;
  }
  EXPECT_TRUE(parser_accepts(parser, "2 + 3 * 4"),
              "expression parser rejected valid input");
  EXPECT_TRUE(!parser_accepts(parser, "2 + * 3"),
              "expression parser accepted invalid input");
  ParseTreeNode* tree = parser_parse_tree(parser, "8 + 5 * 2");
  EXPECT_TRUE(tree != NULL, "expression parser failed to produce a tree");
  if (tree) {
    EXPECT_STREQ(tree->value, "Expr", "expression root mismatch");
    char* dump = getParseTreeAsString(tree);
    EXPECT_TRUE(dump != NULL, "failed to serialise expression parse tree");
    free(dump);
  }
  cparseFreeParseTree(tree);
  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
}

static void test_statement_grammar(void) {
  enum {
    TOK_RETURN,
    TOK_IF,
    TOK_WHILE,
    TOK_IDENTIFIER,
    TOK_NUMBER,
    TOK_LBRACE,
    TOK_RBRACE,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_SEMICOL,
    TOK_ASSIGN,
    TOK_PLUS,
    TOK_STAR,
  };

  static const TokenSpec stmt_specs[] = {
      {"return", TOK_RETURN, "RETURN"},
      {"if", TOK_IF, "IF"},
      {"while", TOK_WHILE, "WHILE"},
      {"[a-zA-Z_]([a-zA-Z_]|[0-9])*", TOK_IDENTIFIER, "IDENTIFIER"},
      {"[0-9]+", TOK_NUMBER, "NUMBER"},
      {"\\{", TOK_LBRACE, "LBRACE"},
      {"\\}", TOK_RBRACE, "RBRACE"},
      {"\\(", TOK_LPAREN, "LPAREN"},
      {"\\)", TOK_RPAREN, "RPAREN"},
      {";", TOK_SEMICOL, "SEMICOL"},
      {"=", TOK_ASSIGN, "ASSIGN"},
      {"\\+", TOK_PLUS, "PLUS"},
      {"\\*", TOK_STAR, "STAR"},
  };

  clexLexer* lexer =
      create_lexer(stmt_specs, sizeof(stmt_specs) / sizeof(stmt_specs[0]));
  if (!lexer) {
    return;
  }

  const char* grammar_src =
      "Program -> Block\n"
      "Block -> LBRACE StmtList RBRACE\n"
      "StmtList -> Stmt StmtList | epsilon\n"
      "Stmt -> RETURN Expr SEMICOL\n"
      "Stmt -> IDENTIFIER ASSIGN Expr SEMICOL\n"
      "Stmt -> IF LPAREN Expr RPAREN Stmt\n"
      "Stmt -> WHILE LPAREN Expr RPAREN Stmt\n"
      "Stmt -> Block\n"
      "Expr -> Term ExprTail\n"
      "ExprTail -> PLUS Term ExprTail | epsilon\n"
      "Term -> Factor TermTail\n"
      "TermTail -> STAR Factor TermTail | epsilon\n"
      "Factor -> IDENTIFIER | NUMBER | LPAREN Expr RPAREN";

  Grammar* grammar = cparseGrammar(grammar_src);
  EXPECT_TRUE(grammar != NULL, "failed to parse statement grammar");
  if (!grammar) {
    clexLexerDestroy(lexer);
    return;
  }

  const char* token_names[] = {
      [TOK_RETURN] = "RETURN", [TOK_IF] = "IF",
      [TOK_WHILE] = "WHILE",   [TOK_IDENTIFIER] = "IDENTIFIER",
      [TOK_NUMBER] = "NUMBER", [TOK_LBRACE] = "LBRACE",
      [TOK_RBRACE] = "RBRACE", [TOK_LPAREN] = "LPAREN",
      [TOK_RPAREN] = "RPAREN", [TOK_SEMICOL] = "SEMICOL",
      [TOK_ASSIGN] = "ASSIGN", [TOK_PLUS] = "PLUS",
      [TOK_STAR] = "STAR",
  };

  LR1Parser* parser =
      cparseCreateLR1Parser(grammar, lexer, token_names,
                            sizeof(token_names) / sizeof(token_names[0]));
  EXPECT_TRUE(parser != NULL, "failed to build statement grammar parser");
  if (!parser) {
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return;
  }

  const char* program = "{ a = b + 1 ; return 42 ; }";

  int expected_tokens[] = {TOK_LBRACE,     TOK_IDENTIFIER, TOK_ASSIGN,
                           TOK_IDENTIFIER, TOK_PLUS,       TOK_NUMBER,
                           TOK_SEMICOL,    TOK_RETURN,     TOK_NUMBER,
                           TOK_SEMICOL,    TOK_RBRACE,     -1};
  clexReset(lexer, program);
  clexToken tok;
  clexTokenInit(&tok);
  for (size_t i = 0; expected_tokens[i] >= 0; ++i) {
    clexStatus lex_status = clex(lexer, &tok);
    char message[128];
    snprintf(message, sizeof(message), "unexpected token kind at position %zu",
             i);
    EXPECT_TRUE(lex_status == CLEX_STATUS_OK, "lexer returned non-OK status");
    EXPECT_TRUE(tok.kind == expected_tokens[i], message);
    if (tok.kind != expected_tokens[i]) {
      break;
    }
  }
  clexTokenClear(&tok);

  clexReset(lexer, program);

  EXPECT_TRUE(parser_accepts(parser, program),
              "statement grammar rejected valid program");

  const char* bad_program = "{ return 42 a = 1 ; }";
  EXPECT_TRUE(!parser_accepts(parser, bad_program),
              "statement grammar accepted invalid program");

  ParseTreeNode* tree = parser_parse_tree(parser, program);
  EXPECT_TRUE(tree != NULL, "statement grammar failed to produce parse tree");
  if (tree) {
    EXPECT_STREQ(tree->value, "Program", "statement grammar root mismatch");
    char* dump = getParseTreeAsString(tree);
    EXPECT_TRUE(dump != NULL, "failed to serialise statement parse tree");
    free(dump);
  }
  cparseFreeParseTree(tree);

  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
}

int main(void) {
  test_first_follow();
  test_lr1_accept_and_tree();
  test_parse_tree_terminals();
  test_lalr_accept();
  test_indexed_parser_tables();
  test_parser_rejects_invalid_input();
  test_parser_rejects_lexical_errors();
  test_conflicting_grammar_is_rejected();
  test_epsilon_grammar();
  test_expression_grammar();
  test_statement_grammar();

  if (failures == 0) {
    printf("All tests passed.\n");
  }
  return failures == 0 ? 0 : 1;
}

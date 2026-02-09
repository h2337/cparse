#include "cparse.h"
#include "clex/clex.h"
#include "lr1_lalr1.h"

#include <stdio.h>
#include <stdlib.h>

static void print_parse_error(const cparseError* error) {
  if (!error) {
    fprintf(stderr, "No parser error available.\n");
    return;
  }
  fprintf(stderr, "Parse error status: %d\n", (int)error->status);
  fprintf(stderr, "At %zu:%zu (offset %zu)\n", error->position.line,
          error->position.column, error->position.offset);
  fprintf(stderr, "Offending lexeme: %s\n",
          error->offending_lexeme ? error->offending_lexeme : "<none>");
  if (error->expected_tokens.size > 0) {
    fprintf(stderr, "Expected:");
    for (size_t i = 0; i < error->expected_tokens.size; ++i) {
      fprintf(stderr, " %s", error->expected_tokens.items[i]);
    }
    fprintf(stderr, "\n");
  }
}

int main(int argc, char **argv) {
  const char *input = argc > 1 ? argv[1] : "8 + 5 * 2";
  fprintf(stderr, "Parsing input: %s\n", input);

  clexLexer *lexer = clexInit();
  if (!lexer) {
    fprintf(stderr, "Failed to initialise lexer.\n");
    return EXIT_FAILURE;
  }
  fprintf(stderr, "Lexer initialised.\n");

  if (clexRegisterKind(lexer, "[0-9]+", 0) != CLEX_STATUS_OK ||
      clexRegisterKind(lexer, "\\+", 1) != CLEX_STATUS_OK ||
      clexRegisterKind(lexer, "\\*", 2) != CLEX_STATUS_OK ||
      clexRegisterKind(lexer, "\\(", 3) != CLEX_STATUS_OK ||
      clexRegisterKind(lexer, "\\)", 4) != CLEX_STATUS_OK) {
    fprintf(stderr, "Failed to register token patterns.\n");
    const clexError* lex_error = clexGetLastError(lexer);
    if (lex_error) {
      fprintf(stderr, "Lexer error status: %d\n", (int)lex_error->status);
      fprintf(stderr, "Offending regex/text: %s\n",
              lex_error->offending_lexeme ? lex_error->offending_lexeme
                                          : "<none>");
    }
    clexLexerDestroy(lexer);
    return EXIT_FAILURE;
  }
  fprintf(stderr, "Token patterns registered.\n");

  const char *grammar_src =
      "Expr -> Term ExprTail\n"
      "ExprTail -> PLUS Term ExprTail | epsilon\n"
      "Term -> Factor TermTail\n"
      "TermTail -> STAR Factor TermTail | epsilon\n"
      "Factor -> NUMBER | LPAREN Expr RPAREN";

  Grammar *grammar = cparseGrammar(grammar_src);
  if (!grammar) {
    fprintf(stderr, "Failed to build grammar.\n");
    clexLexerDestroy(lexer);
    return EXIT_FAILURE;
  }
  fprintf(stderr, "Grammar constructed.\n");

  const char *token_names[] = {"NUMBER", "PLUS", "STAR", "LPAREN", "RPAREN"};
  LALR1Parser *parser =
      cparseCreateLALR1Parser(grammar, lexer, token_names,
                              sizeof(token_names) / sizeof(token_names[0]));
  if (!parser) {
    fprintf(stderr, "Failed to create parser.\n");
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return EXIT_FAILURE;
  }
  fprintf(stderr, "Parser constructed.\n");

  cparseStatus accept_status = cparseAccept(parser, input);
  if (accept_status != CPARSE_STATUS_OK) {
    fprintf(stderr, "Input rejected: %s\n", input);
    print_parse_error(cparseGetLastError(parser));
    cparseFreeParser(parser);
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return EXIT_FAILURE;
  }
  fprintf(stderr, "Input accepted.\n");

  ParseTreeNode *tree = NULL;
  cparseStatus parse_status = cparse(parser, input, &tree);
  if (parse_status != CPARSE_STATUS_OK || !tree) {
    fprintf(stderr, "Parsing failed unexpectedly.\n");
    print_parse_error(cparseGetLastError(parser));
    cparseFreeParser(parser);
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return EXIT_FAILURE;
  }
  fprintf(stderr, "Parse tree constructed.\n");

  char *tree_str = getParseTreeAsString(tree);
  if (!tree_str) {
    fprintf(stderr, "Failed to render parse tree.\n");
    cparseFreeParseTree(tree);
    cparseFreeParser(parser);
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return EXIT_FAILURE;
  }
  printf("Parse tree for '%s':\n%s", input, tree_str);
  free(tree_str);
  cparseFreeParseTree(tree);

  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
  return EXIT_SUCCESS;
}

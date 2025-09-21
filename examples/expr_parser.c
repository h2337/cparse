#include "cparse.h"
#include "clex/clex.h"
#include "lr1_lalr1.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  const char *input = argc > 1 ? argv[1] : "8 + 5 * 2";
  fprintf(stderr, "Parsing input: %s\n", input);

  clexLexer *lexer = clexInit();
  if (!lexer) {
    fprintf(stderr, "Failed to initialise lexer.\n");
    return EXIT_FAILURE;
  }
  fprintf(stderr, "Lexer initialised.\n");

  if (!clexRegisterKind(lexer, "[0-9]+", 0) ||
      !clexRegisterKind(lexer, "\\+", 1) ||
      !clexRegisterKind(lexer, "\\*", 2) ||
      !clexRegisterKind(lexer, "\\(", 3) ||
      !clexRegisterKind(lexer, "\\)", 4)) {
    fprintf(stderr, "Failed to register token patterns.\n");
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
  LALR1Parser *parser = cparseCreateLALR1Parser(grammar, lexer, token_names);
  if (!parser) {
    fprintf(stderr, "Failed to create parser.\n");
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return EXIT_FAILURE;
  }
  fprintf(stderr, "Parser constructed.\n");

  if (!cparseAccept(parser, input)) {
    fprintf(stderr, "Input rejected: %s\n", input);
    cparseFreeParser(parser);
    cparseFreeGrammar(grammar);
    clexLexerDestroy(lexer);
    return EXIT_FAILURE;
  }
  fprintf(stderr, "Input accepted.\n");

  ParseTreeNode *tree = cparse(parser, input);
  if (!tree) {
    fprintf(stderr, "Parsing failed unexpectedly.\n");
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


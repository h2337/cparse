#ifdef TEST_CPARSE

#include "grammar.h"
#include "lr1.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
  char grammarString[] = "S -> A A\nA -> a A | b\nB -> #";
  Grammar *grammar = parseGrammar(grammarString);
  printf("%s\n", getGrammarAsString(grammar));

  printf("\n");

  char grammarString2[] = "Program -> var Variables begin Operators end\n"
                          "Variables -> Variable ; Variables\n"
                          "Variables -> #\n"
                          "Variable -> identifier\n"
                          "Operators -> Operator ; Operators\n"
                          "Operators -> #\n"
                          "Operator -> read ( Variable )\n"
                          "Operator -> write ( Variable )\n";
  Grammar *grammar2 = parseGrammar(grammarString2);
  printf("%s\n", getGrammarAsString(grammar2));

  printf("\n");

  char grammarString3[] = "P -> E\n"
                          "E -> E + T\n"
                          "E -> T\n"
                          "T -> id ( E )\n"
                          "T -> id\n";
  Grammar *grammar3 = parseGrammar(grammarString3);
  printf("%s\n", getGrammarAsString(grammar3));

  printf("\n");

  LR1Parser *parser = createLR1Parser(grammar2);
  printf("%s\n", getLR1ParserAsString(parser));
}

#endif


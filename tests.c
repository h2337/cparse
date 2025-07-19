#ifdef TEST_CPARSE

#include "grammar.h"
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
  grammar = parseGrammar(grammarString2);
  printf("%s\n", getGrammarAsString(grammar));
}

#endif

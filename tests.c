#ifdef TEST_CPARSE

#include "grammar.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
  char grammarString[] = "S -> A A\nA -> a A | b";
  Grammar *grammar = parseGrammar(grammarString);
  printf("%s\n", getGrammarAsString(grammar));
}

#endif

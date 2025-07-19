#include "lr1.h"
#include <stdlib.h>

LR1Parser *createLR1Parser(Grammar *grammar) {
  return calloc(1, sizeof(LR1Parser));
}

char *getLR1ParserAsString(LR1Parser *parser) {
  return "LR1Parser";
}


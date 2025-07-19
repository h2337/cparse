#ifndef CPARSE_LR1_H
#define CPARSE_LR1_H

#include "cparse.h"

char *getLR1ParserAsString(LR1Parser *parser);
char *getParseTreeAsString(ParseTreeNode *node);

#endif


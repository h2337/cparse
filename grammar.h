#ifndef CPARSE_GRAMMAR_H
#define CPARSE_GRAMMAR_H

#include "util.h"

typedef struct Rule {
  char *left;
  char **right;
} Rule;

typedef struct Grammar {
  Rule **rules;
  char **terminals;
  char **nonterminals;
  char *start;
  SetItem **first;
  SetItem **follow;
} Grammar;

Grammar *parseGrammar(char *grammarString);
char *getGrammarAsString(Grammar *grammar);

#endif


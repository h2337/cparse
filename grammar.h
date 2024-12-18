#ifndef GRAMMAR_H
#define GRAMMAR_H

typedef struct SetItem {
  char *key;
  char **values;
} SetItem;

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

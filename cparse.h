#ifndef CPARSE_H
#define CPARSE_H

#include "clex/clex.h"
#include <stdbool.h>

#define ARRAY_CAPACITY 2048

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

typedef struct LR1Item {
  char **lookaheads;
  char *left;
  char **right;
  int dot;
} LR1Item;

typedef struct LR1State LR1State;

typedef struct LR1Transition {
  char *value;
  LR1State *state;
} LR1Transition;

typedef struct LR1State {
  LR1Item **items;
  LR1Transition **transitions;
} LR1State;

typedef struct GoToNode {
  char *nonterminal;
  int state;
} GoToNode;

typedef enum ActionType {
  ACCEPT,
  SHIFT,
  REDUCE
} ActionType;

typedef struct Action {
  ActionType type;
  int operand;
} Action;

typedef struct ActionNode {
  char *terminal;
  Action *action;
} ActionNode;

typedef struct LR1Parser {
  Grammar *grammar;
  LR1State **collection;
  GoToNode ***goToTable;
  ActionNode ***actionTable;
  const char * const *tokenKindStr;
} LR1Parser;

typedef LR1Parser LALR1Parser;

typedef struct ParseTreeNode ParseTreeNode;

typedef struct ParseTreeNode {
  char *value;
  Token token;
  ParseTreeNode **children;
} ParseTreeNode;

Grammar *cparseGrammar(char *grammarString);
LR1Parser *cparseCreateLR1Parser(Grammar *grammar, const char * const *tokenKindStr);
LALR1Parser *cparseCreateLALR1Parser(Grammar *grammar, const char * const *tokenKindStr);
bool cparseAccept(LR1Parser *parser, char *input);
ParseTreeNode *cparse(LR1Parser *parser, char *input);

#endif

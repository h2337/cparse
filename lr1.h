#ifndef CPARSE_LR1_H
#define CPARSE_LR1_H

#include "grammar.h"

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

typedef struct ParseTreeNode ParseTreeNode;

typedef struct ParseTreeNode {
  char *value;
  ParseTreeNode **children;
} ParseTreeNode;

LR1Parser *createLR1Parser(Grammar *grammar, const char * const *tokenKindStr);
char *getLR1ParserAsString(LR1Parser *parser);
char *getParseTreeAsString(ParseTreeNode *node);
ParseTreeNode *parse(LR1Parser *parser, char *input);
bool accept(LR1Parser *parser, char *input);

#endif


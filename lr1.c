#include "lr1.h"
#include "grammar.h"
#include <stdlib.h>

LR1Parser *makeParser() {
  LR1Parser *parser = calloc(1, sizeof(LR1Parser));
  parser->collection = calloc(1024, sizeof(LR1State *));
  parser->gotoTable = calloc(1024, sizeof(GoToNode *));
  parser->actionTable = calloc(1024, sizeof(ActionNode *));
  return parser;
}

LR1Item *makeLR1Item(char *left, char **right, int dot, char **lookaheads) {
  LR1Item *item = calloc(1, sizeof(LR1Item));
  item->left = left;
  item->right = right;
  item->dot = dot;
  item->lookaheads = lookaheads;
  return item;
}

void closure(Grammar *grammar, LR1Item **items) {
  return;
}

LR1State *makeLR1State(Grammar *grammar, LR1Item **items) {
  LR1State *state = calloc(1, sizeof(LR1State));
  state->items = items;
  state->transitions = calloc(1024, sizeof(LR1Transition *));
  closure(grammar, state->items);
  return state;
}

void createCollection(LR1Parser *parser, Grammar *grammar) {
  LR1Item **startItems = calloc(1024, sizeof(LR1Item *));
  char **startLookahead = calloc(1024, sizeof(char *));
  startLookahead[0] = "$";
  Rule *firstRule = grammar->rules[0];
  startItems[0] = makeLR1Item(firstRule->left, firstRule->right, 0, startLookahead);
  LR1State *startState = makeLR1State(grammar, startItems);
  parser->collection[0] = startState;
}

LR1Parser *createLR1Parser(Grammar *grammar) {
  LR1Parser *parser = makeParser();
  createCollection(parser, grammar);
  return parser;
}

char *getLR1ParserAsString(LR1Parser *parser) {
  return "LR1Parser";
}


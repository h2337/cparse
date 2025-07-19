#include "lr1.h"
#include "grammar.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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

bool isNonTerminal(Grammar *grammar, char *value) {
  for (int i = 0; i < 1024; i++)
    if (grammar->nonterminals[i] && strcmp(grammar->nonterminals[i], value) == 0)
      return true;
  return false;
}

char **computeFirstByIndex(Grammar *grammar, char **strings, int index) {
  char **result = calloc(1024, sizeof(char *));
  if (index == getValuesLength(strings))
    return result;
  if (inArray(grammar->terminals, strings[index]) || strcmp(strings[index], "#") == 0) {
    addCharPtrToArray(result, strings[index]);
    return result;
  }
  if (inArray(grammar->nonterminals, strings[index]))
    addAllCharPtrToArrayUnique(result, findValuesInSet(grammar->first, strings[index]));
  if (inArray(result, "#"))
    if (index != getValuesLength(strings) - 1) {
      removeCharPtrFromArray(result, "#");
      addAllCharPtrToArrayUnique(result, computeFirstByIndex(grammar, strings, index + 1));
    }
  return result;
}

bool equalLR0(LR1Item *a, LR1Item *b) {
  if (a->dot != b->dot)
    return false;
  if (strcmp(a->left, b->left) != 0)
    return false;
  if (!isArrayEqual(a->right, b->right))
    return false;
  return true;
}

void addItem(LR1Item **items, LR1Item *item) {
  for (int i = 0; i < 1024; i++)
    if (!items[i]) {
      items[i] = item;
      break;
    }
}

void closure(Grammar *grammar, LR1Item **items) {
  bool changed = false;
  do {
    changed = false;
    for (int i = 0; i < 1024; i++) {
      if (items[i]) {
        if (items[i]->dot != getValuesLength(items[i]->right) && isNonTerminal(grammar, items[i]->right[items[i]->dot])) {
          char **lookaheads = calloc(1024, sizeof(char *));
          if (items[i]->dot == getValuesLength(items[i]->right) - 1) {
            addAllCharPtrToArrayUnique(lookaheads, items[i]->lookaheads);
          } else {
            char **firstSet = computeFirstByIndex(grammar, items[i]->right, items[i]->dot + 1);
            if (inArray(firstSet, "#")) {
              removeCharPtrFromArray(firstSet, "#");
              addAllCharPtrToArrayUnique(firstSet, items[i]->lookaheads);
            }
            addAllCharPtrToArrayUnique(lookaheads, firstSet);
          }
          for (int j = 0; j < 1024; j++) {
            if (grammar->rules[j] && strcmp(grammar->rules[j]->left, items[i]->right[items[i]->dot]) == 0) {
              char **right = grammar->rules[j]->right;
              int finish = 0;
              if (getValuesLength(right) == 1 && strcmp(right[0], "#") == 0)
                finish = 1;
              char **newLookaheads = copyCharArray(lookaheads);
              LR1Item *newItem = makeLR1Item(grammar->rules[j]->left, right, finish, newLookaheads);
              bool found = false;
              for (int x = 0; x < 1024; x++) {
                if (items[x]) {
                  if (equalLR0(items[x], newItem)) {
                    if (!arrayContainsAll(items[x]->lookaheads, newLookaheads)) {
                      addAllCharPtrToArrayUnique(items[x]->lookaheads, newLookaheads);
                      changed = true;
                    }
                    found = true;
                    break;
                  }
                }
              }
              if (!found) {
                addItem(items, newItem);
                changed = true;
              }
            }
          }
          if (changed)
            break;
        }
      }
    }
  } while (changed);
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

int getIndexOfState(LR1State **collection, LR1State *state) {
  for (int i = 0; i < 1024; i++)
    if (collection[i] && collection[i] == state)
      return i;
}

char *getCharPtrArrayAsString(char **array) {
  char *result = calloc(10000, sizeof(char));
  for (int i = 0; i < 1024; i++)
    if (array[i])
      sprintf(result + strlen(result), "%s, ", array[i]);
  return result;
}

char *getLR1ParserAsString(LR1Parser *parser) {
  char *result = calloc(100000, sizeof(char));
  sprintf(result, "Collection:\n");
  for (int i = 0; i < 1024; i++) {
    if (parser->collection[i]) {
      sprintf(result + strlen(result), "State %d:\n", i);
      sprintf(result + strlen(result), "Items:\n");
      for (int j = 0; j < 1024; j++) {
        if (parser->collection[i]->items[j]) {
          sprintf(result + strlen(result), "%s -> %s\n", parser->collection[i]->items[j]->left, getCharPtrArrayAsString(parser->collection[i]->items[j]->right));
          sprintf(result + strlen(result), "Dot: %d\n", parser->collection[i]->items[j]->dot);
          sprintf(result + strlen(result), "Lookaheads: %s\n", getCharPtrArrayAsString(parser->collection[i]->items[j]->lookaheads));
        }
      }
      sprintf(result + strlen(result), "Transitions:\n");
      for (int j = 0; j < 1024; j++) {
        if (parser->collection[i]->transitions[j]) {
          sprintf(result + strlen(result), "%s -> %d\n", parser->collection[i]->transitions[j]->value, getIndexOfState(parser->collection, parser->collection[i]->transitions[j]->state));
        }
      }
    }
  }
  return result;
}


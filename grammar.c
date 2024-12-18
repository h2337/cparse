#include "cparse.h"
#include "grammar.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

Grammar *makeGrammar() {
  Grammar *grammar = calloc(1, sizeof(Grammar));
  grammar->rules = calloc(ARRAY_CAPACITY, sizeof(Rule *));
  grammar->terminals = calloc(ARRAY_CAPACITY, sizeof(char *));
  grammar->nonterminals = calloc(ARRAY_CAPACITY, sizeof(char *));
  grammar->first = makeSet();
  grammar->follow = makeSet();
  return grammar;
}

Rule *makeRule() {
  Rule *rule = calloc(1, sizeof(Rule));
  rule->right = calloc(ARRAY_CAPACITY, sizeof(char *));
  return rule;
}

void addRuleToArray(Rule **array, Rule *value) {
  for (int i = 0; i < ARRAY_CAPACITY; i++) {
    if (!array[i]) {
      array[i] = value;
      break;
    }
  }
}

void computeFirst(Grammar *grammar, char *nonterminal) {
  for (int j = 0; j < ARRAY_CAPACITY; j++) {
    if (grammar->rules[j] && strcmp(grammar->rules[j]->left, nonterminal) == 0) {
      if (grammar->rules[j]->right[0]) {
        if (strcmp(grammar->rules[j]->right[0], "#") == 0) {
          addToSet(grammar->first, nonterminal, "#");
        } else if (inArray(grammar->terminals, grammar->rules[j]->right[0])) {
          addToSet(grammar->first, nonterminal, grammar->rules[j]->right[0]);
        } else if (inArray(grammar->nonterminals, grammar->rules[j]->right[0])) {
          int count = 0;
          if (strcmp(grammar->rules[j]->left, grammar->rules[j]->right[count]) != 0)
            computeFirst(grammar, grammar->rules[j]->right[count]);
          if (!inSet(grammar->first, grammar->rules[j]->right[count], "#")) {
            addAllToSet(grammar->first, nonterminal, findValuesInSet(grammar->first, grammar->rules[j]->right[0]));
          } else {
            addAllToSet(grammar->first, nonterminal, findValuesInSet(grammar->first, grammar->rules[j]->right[0])); // TODO: Minus epsilon?
            while (true) {
              computeFirst(grammar, grammar->rules[j]->right[++count]);
              addAllToSet(grammar->first, nonterminal, findValuesInSet(grammar->first, grammar->rules[j]->right[count]));
              if (!inSet(grammar->first, grammar->rules[j]->right[count], "#"))
                break;
            }
          }
        }
      }
    }
  }
}

void computeFirstSet(Grammar *grammar) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (grammar->nonterminals[i])
      computeFirst(grammar, grammar->nonterminals[i]);
}

void computeFollowSet(Grammar *grammar) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (grammar->nonterminals[i] && !isKeyInSet(grammar->follow, grammar->nonterminals[i]))
      createSetItem(grammar->follow, grammar->nonterminals[i]);
  while (true) {
    bool hasChanged = false;
    for (int i = 0; i < ARRAY_CAPACITY; i++) {
      if (grammar->nonterminals[i]) {
        char *nonterminal = grammar->nonterminals[i];
        if (strcmp(nonterminal, "cparseStart") == 0) {
          addToSet(grammar->follow, nonterminal, "$");
          continue;
        }
        for (int i = 0; i < ARRAY_CAPACITY; i++) {
          if (grammar->rules[i]) {
            for (int j = 0; j < ARRAY_CAPACITY; j++) {
              if (grammar->rules[i]->right[j] && strcmp(grammar->rules[i]->right[j], nonterminal) == 0) {
                SetItem *first = NULL;
                if (j == getValuesLength(grammar->rules[i]->right) - 1) {
                  first = findInSet(grammar->follow, grammar->rules[i]->left);
                } else {
                  SetItem *rightFirst = findInSet(grammar->first, grammar->rules[i]->right[j + 1]);
                  if (rightFirst)
                    first = copySetItem(rightFirst); // TODO: Why copy?
                  else {
                    first = calloc(1, sizeof(SetItem));
                    first->values = calloc(ARRAY_CAPACITY, sizeof(SetItem));
                    first->values[0] = grammar->rules[i]->right[j + 1];
                  }
                  if (inSetItem(first, "#")) {
                    removeFromSetItem(first, "#");
                    addAllToSetItem(first, findValuesInSet(grammar->follow, grammar->rules[i]->left));
                  }
                }
                SetItem *follow = findInSet(grammar->follow, nonterminal);
                if (!allInSetItem(follow, first->values)) {
                  hasChanged = true;
                  addAllToSetItem(follow, first->values);
                }
              }
            }
          }
        }
      }
    }
    if (!hasChanged) break;
  }
}

Grammar *parseGrammar(char *grammarString) {
  Grammar *grammar = makeGrammar();
  char *rest, *token, *grammarStringPtr = grammarString;
  while ((token = strtok_r(grammarStringPtr, "\n", &rest))) {
    char *left = trim(strtok(token, "->"));
    if (!grammar->start) {
      grammar->start = left;
      Rule *rule = makeRule();
      rule->left = "cparseStart";
      addCharPtrToArray(rule->right, left);
      addRuleToArray(grammar->rules, rule);
      addCharPtrToArray(grammar->nonterminals, "cparseStart");
    }
    addCharPtrToArray(grammar->nonterminals, left);
    char *right = strtok(NULL, "->");
    char *singleRight = strtok(right, "|");
    while (singleRight) {
      singleRight = trim(singleRight);
      char **singleRightWords = stringToWords(singleRight);
      for (int i = 0; i < ARRAY_CAPACITY; i++)
        if (singleRightWords[i] && strcmp(singleRightWords[i], "#") != 0)
          addCharPtrToArray(grammar->terminals, singleRightWords[i]);
      Rule *rule = makeRule();
      rule->left = left;
      rule->right = singleRightWords;
      addRuleToArray(grammar->rules, rule);
      singleRight = strtok(NULL, "|");
    }
    grammarStringPtr = rest;
  }
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (grammar->nonterminals[i])
      removeCharPtrFromArray(grammar->terminals, grammar->nonterminals[i]);
  computeFirstSet(grammar);
  computeFollowSet(grammar);
  return grammar;
}

char *getGrammarAsString(Grammar *grammar) {
  char *result = calloc(100000, sizeof(char));
  sprintf(result, "Start nonterminal: ");
  sprintf(result + strlen(result), grammar->start);
  sprintf(result + strlen(result), "\nTerminals:");
  for (int i = 0; i < ARRAY_CAPACITY; i++) {
    if (grammar->terminals[i]) {
      sprintf(result + strlen(result), " ");
      sprintf(result + strlen(result), grammar->terminals[i]);
    }
  }
  sprintf(result + strlen(result), "\nNon-terminals:");
  for (int i = 0; i < ARRAY_CAPACITY; i++) {
    if (grammar->nonterminals[i]) {
      sprintf(result + strlen(result), " ");
      sprintf(result + strlen(result), grammar->nonterminals[i]);
    }
  }
  sprintf(result + strlen(result), "\nRules: ");
  for (int i = 0; i < ARRAY_CAPACITY; i++) {
    if (grammar->rules[i]) {
      sprintf(result + strlen(result), grammar->rules[i]->left);
      sprintf(result + strlen(result), " ->");
      for (int j = 0; j < ARRAY_CAPACITY; j++) {
        if (grammar->rules[i]->right[j]) {
          sprintf(result + strlen(result), " ");
          sprintf(result + strlen(result), grammar->rules[i]->right[j]);
        }
      }
      sprintf(result + strlen(result), " && ");
    }
  }
  result[strlen(result) - 4] = '\0';
  sprintf(result + strlen(result), "\nFirst set:");
  for (int i = 0; i < ARRAY_CAPACITY; i++) {
    if (grammar->first[i]) {
      sprintf(result + strlen(result), " ");
      sprintf(result + strlen(result), grammar->first[i]->key);
      sprintf(result + strlen(result), ": [");
      for (int j = 0; j < ARRAY_CAPACITY; j++) {
        if (grammar->first[i]->values[j]) {
          sprintf(result + strlen(result), grammar->first[i]->values[j]);
          sprintf(result + strlen(result), ", ");
        }
      }
      result[strlen(result) - 2] = '\0';
      sprintf(result + strlen(result), "]");
    }
  }
  sprintf(result + strlen(result), "\nFollow set:");
  for (int i = 0; i < ARRAY_CAPACITY; i++) {
    bool empty = true;
    if (grammar->follow[i]) {
      sprintf(result + strlen(result), " ");
      sprintf(result + strlen(result), grammar->follow[i]->key);
      sprintf(result + strlen(result), ": [");
      for (int j = 0; j < ARRAY_CAPACITY; j++) {
        if (grammar->follow[i]->values[j]) {
          empty = false;
          sprintf(result + strlen(result), grammar->follow[i]->values[j]);
          sprintf(result + strlen(result), ", ");
        }
      }
      if (!empty) result[strlen(result) - 2] = '\0';
      sprintf(result + strlen(result), "]");
    }
  }
  return result;
}


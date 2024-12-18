#include "grammar.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

Grammar *makeGrammar() {
  Grammar *grammar = calloc(1, sizeof(Grammar));
  grammar->rules = calloc(1024, sizeof(Rule *));
  grammar->terminals = calloc(1024, sizeof(char *));
  grammar->nonterminals = calloc(1024, sizeof(char *));
  return grammar;
}

char *trim(char *str) {
  char *end;
  while (isspace((unsigned char)*str)) str++;
  if (*str == 0) return str;
  end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end)) end--;
  end[1] = '\0';
  return str;
}

void addCharPtrToArray(char **array, char *value) {
  for (int i = 0; i < 1024; i++) {
    if (!array[i]) {
      array[i] = value;
      break;
    }
  }
}

void removeCharPtrFromArray(char **array, char *value) {
  for (int i = 0; i < 1024; i++)
    if (array[i] && strcmp(array[i], value) == 0)
      array[i] = NULL;
}

void addRuleToArray(Rule **array, Rule *value) {
  for (int i = 0; i < 1024; i++) {
    if (!array[i]) {
      array[i] = value;
      break;
    }
  }
}

Rule *makeRule() {
  Rule *rule = calloc(1, sizeof(Rule));
  rule->right = calloc(1024, sizeof(char *));
  return rule;
}

char **stringToWords(char *string) {
  char **result = calloc(1024, sizeof(char *));
  char *rest, *token, *stringPtr = string;
  while (token = strtok_r(stringPtr, " ", &rest)) {
    addCharPtrToArray(result, token);
    stringPtr = rest;
  }
  return result;
}

Grammar *parseGrammar(char *grammarString) {
  Grammar *grammar = makeGrammar();
  char *rest, *token, *grammarStringPtr = grammarString;
  while (token = strtok_r(grammarStringPtr, "\n", &rest)) {
    char *left = trim(strtok(token, "->"));
    if (!grammar->start) {
      grammar->start = left;
      Rule *rule = makeRule();
      rule->left = "cparseStart";
      addCharPtrToArray(rule->right, left);
      addRuleToArray(grammar->rules, rule);
    }
    addCharPtrToArray(grammar->nonterminals, left);
    char *right = strtok(NULL, "->");
    char *singleRight = strtok(right, "|");
    while (singleRight) {
      singleRight = trim(singleRight);
      char **singleRightWords = stringToWords(singleRight);
      for (int i = 0; i < 1024; i++)
        if (singleRightWords[i] && strcmp(singleRightWords[i], "epsilon") != 0)
          addCharPtrToArray(grammar->terminals, singleRightWords[i]);
      Rule *rule = makeRule();
      rule->left = left;
      rule->right = singleRightWords;
      addRuleToArray(grammar->rules, rule);
      singleRight = strtok(NULL, "|");
    }
    grammarStringPtr = rest;
  }
  for (int i = 0; i < 1024; i++)
    if (grammar->nonterminals[i])
      removeCharPtrFromArray(grammar->terminals, grammar->nonterminals[i]);
  return grammar;
}

char *getGrammarAsString(Grammar *grammar) {
  char *result = calloc(100000, sizeof(char));
  sprintf(result, "Start nonterminal: ");
  sprintf(result + strlen(result), grammar->start);
  sprintf(result + strlen(result), "\nTerminals:");
  for (int i = 0; i < 1024; i++) {
    if (grammar->terminals[i]) {
      sprintf(result + strlen(result), " ");
      sprintf(result + strlen(result), grammar->terminals[i]);
    }
  }
  sprintf(result + strlen(result), "\nNon-terminals:");
  for (int i = 0; i < 1024; i++) {
    if (grammar->nonterminals[i]) {
      sprintf(result + strlen(result), " ");
      sprintf(result + strlen(result), grammar->nonterminals[i]);
    }
  }
  sprintf(result + strlen(result), "\nRules: ");
  for (int i = 0; i < 1024; i++) {
    if (grammar->rules[i]) {
      sprintf(result + strlen(result), grammar->rules[i]->left);
      sprintf(result + strlen(result), " ->");
      for (int j = 0; j < 1024; j++) {
        if (grammar->rules[i]->right[j]) {
          sprintf(result + strlen(result), " ");
          sprintf(result + strlen(result), grammar->rules[i]->right[j]);
        }
      }
      sprintf(result + strlen(result), " && ");
    }
  }
  return result;
}

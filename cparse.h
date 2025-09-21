#ifndef CPARSE_H
#define CPARSE_H

#include <stdbool.h>
#include <stddef.h>

#include "clex/clex.h"
#include "util.h"

#define CPARSE_EPSILON "epsilon"
#define CPARSE_START_SYMBOL "cparseStart"

typedef struct Rule {
  char *left;
  StringVec right;
} Rule;

typedef struct Grammar {
  PtrVec rules; /* Rule* */
  StringVec terminals;
  StringVec nonterminals;
  char *start; /* user provided start symbol */
  SymbolSet first;
  SymbolSet follow;
} Grammar;

typedef struct LR1Item {
  Rule *rule;
  size_t dot;
  StringVec lookahead; /* char* entries reference grammar symbols */
} LR1Item;

typedef struct LR1State LR1State;

typedef struct LR1Transition {
  const char *symbol;
  LR1State *state;
} LR1Transition;

struct LR1State {
  PtrVec items;       /* LR1Item* */
  PtrVec transitions; /* LR1Transition* */
};

typedef struct GoToNode {
  const char *symbol;
  size_t state;
} GoToNode;

typedef enum ActionType {
  ACTION_ACCEPT,
  ACTION_SHIFT,
  ACTION_REDUCE
} ActionType;

typedef struct Action {
  ActionType type;
  size_t operand; /* shift target, reduce rule index */
} Action;

typedef struct ActionEntry {
  const char *terminal;
  Action action;
} ActionEntry;

typedef struct LR1Parser {
  Grammar *grammar;
  clexLexer *lexer;    /* not owned */
  PtrVec collection;   /* LR1State* */
  PtrVec goto_table;   /* PtrVec* where PtrVec holds GoToNode* */
  PtrVec action_table; /* PtrVec* where PtrVec holds ActionEntry* */
  const char *const *tokenKindStr;
} LR1Parser;

typedef LR1Parser LALR1Parser;

typedef struct ParseTreeNode ParseTreeNode;

typedef struct ParseTreeNode {
  char *value;
  clexToken token;
  PtrVec children; /* ParseTreeNode* */
} ParseTreeNode;

Grammar *cparseGrammar(const char *grammarString);
LR1Parser *cparseCreateLR1Parser(Grammar *grammar, clexLexer *lexer,
                                 const char *const *tokenKindStr);
LALR1Parser *cparseCreateLALR1Parser(Grammar *grammar, clexLexer *lexer,
                                     const char *const *tokenKindStr);
bool cparseAccept(LR1Parser *parser, const char *input);
ParseTreeNode *cparse(LR1Parser *parser, const char *input);
void cparseFreeParseTree(ParseTreeNode *node);
void cparseFreeParser(LR1Parser *parser);
void cparseFreeGrammar(Grammar *grammar);

#endif

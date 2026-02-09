#ifndef CPARSE_H
#define CPARSE_H

#include <stdbool.h>
#include <stddef.h>

#include "clex/clex.h"
#include "util.h"

#define CPARSE_EPSILON "epsilon"
#define CPARSE_START_SYMBOL "cparseStart"

typedef struct Rule {
  char* left;
  StringVec right;
} Rule;

typedef struct Grammar {
  PtrVec rules; /* Rule* */
  StringVec terminals;
  StringVec nonterminals;
  char* start; /* user provided start symbol */
  SymbolSet first;
  SymbolSet follow;
} Grammar;

typedef struct LR1Item {
  Rule* rule;
  size_t dot;
  StringVec lookahead; /* char* entries reference grammar symbols */
} LR1Item;

typedef struct LR1State LR1State;

typedef struct LR1Transition {
  const char* symbol;
  LR1State* state;
} LR1Transition;

struct LR1State {
  PtrVec items;       /* LR1Item* */
  PtrVec transitions; /* LR1Transition* */
};

typedef struct GoToNode {
  const char* symbol;
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
  const char* terminal;
  Action action;
} ActionEntry;

typedef enum cparseStatus {
  CPARSE_STATUS_OK = 0,
  CPARSE_STATUS_INVALID_ARGUMENT,
  CPARSE_STATUS_OUT_OF_MEMORY,
  CPARSE_STATUS_LEXICAL_ERROR,
  CPARSE_STATUS_UNEXPECTED_TOKEN,
  CPARSE_STATUS_INVALID_TOKEN_KIND,
  CPARSE_STATUS_INTERNAL_ERROR
} cparseStatus;

typedef struct cparseError {
  cparseStatus status;
  clexSourcePosition position;
  char* offending_lexeme;
  StringVec expected_tokens; /* owned strings */
  int offending_token_kind;
  size_t parser_state;
} cparseError;

typedef struct LR1Parser {
  Grammar* grammar;
  clexLexer* lexer;  /* not owned */
  PtrVec collection; /* LR1State* */
  size_t state_count;
  size_t terminal_count;
  size_t nonterminal_count;
  const char** terminal_symbols;     /* terminal id -> symbol, includes "$" */
  const char** nonterminal_symbols;  /* nonterminal id -> symbol */
  ptrdiff_t* token_kind_to_terminal; /* token kind -> terminal id */
  ptrdiff_t* rule_nonterminal_ids;   /* rule index -> nonterminal id */
  ptrdiff_t* goto_table;             /* [state][nonterminal_id] -> next state */
  ActionEntry* action_table;         /* [state][terminal_id] -> action */
  unsigned char* action_present;     /* [state][terminal_id] presence */
  const char* const* tokenKindStr;
  size_t tokenKindCount;
  cparseError last_error;
} LR1Parser;

typedef LR1Parser LALR1Parser;

typedef struct ParseTreeNode ParseTreeNode;

typedef struct ParseTreeNode {
  char* value;
  clexToken token;
  clexSourceSpan span;
  PtrVec children; /* ParseTreeNode* */
} ParseTreeNode;

Grammar* cparseGrammar(const char* grammarString);
LR1Parser* cparseCreateLR1Parser(Grammar* grammar, clexLexer* lexer,
                                 const char* const* tokenKindStr,
                                 size_t tokenKindCount);
LALR1Parser* cparseCreateLALR1Parser(Grammar* grammar, clexLexer* lexer,
                                     const char* const* tokenKindStr,
                                     size_t tokenKindCount);
cparseStatus cparseAccept(LR1Parser* parser, const char* input);
cparseStatus cparse(LR1Parser* parser, const char* input,
                    ParseTreeNode** out_tree);
const cparseError* cparseGetLastError(const LR1Parser* parser);
void cparseClearError(cparseError* error);
void cparseFreeParseTree(ParseTreeNode* node);
void cparseFreeParser(LR1Parser* parser);
void cparseFreeGrammar(Grammar* grammar);

#endif

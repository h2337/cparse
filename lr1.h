#ifndef CPARSE_LR1_H
#define CPARSE_LR1_H

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

#endif


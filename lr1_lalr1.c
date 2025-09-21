#include "lr1_lalr1.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "clex/clex.h"
#include "cparse.h"

static const char *kEndMarker = "$";

static void free_token(clexToken *token) {
  if (!token) {
    return;
  }
  free(token->lexeme);
  token->lexeme = NULL;
}

static bool grammar_is_terminal(const Grammar *grammar, const char *symbol) {
  if (!symbol || strcmp(symbol, CPARSE_EPSILON) == 0) {
    return false;
  }
  return string_vec_contains(&grammar->terminals, symbol) &&
         !string_vec_contains(&grammar->nonterminals, symbol);
}

static bool grammar_is_nonterminal(const Grammar *grammar, const char *symbol) {
  return string_vec_contains(&grammar->nonterminals, symbol);
}

static bool rule_is_epsilon(const Rule *rule) {
  return rule->right.size == 1 &&
         strcmp(rule->right.items[0], CPARSE_EPSILON) == 0;
}

static size_t rule_symbol_count(const Rule *rule) {
  return rule_is_epsilon(rule) ? 0 : rule->right.size;
}

static LR1Item *lr1_item_create(Rule *rule, size_t dot) {
  LR1Item *item = calloc(1, sizeof(*item));
  if (!item) {
    return NULL;
  }
  item->rule = rule;
  item->dot = dot;
  string_vec_init(&item->lookahead);
  return item;
}

static void lr1_item_destroy(void *ptr) {
  LR1Item *item = ptr;
  if (!item) {
    return;
  }
  string_vec_free(&item->lookahead, false);
  free(item);
}

static bool lr1_item_add_lookahead(LR1Item *item, const char *terminal,
                                   bool *added) {
  size_t before = item->lookahead.size;
  if (!string_vec_push_unique(&item->lookahead, (char *)terminal)) {
    return false;
  }
  if (added && item->lookahead.size != before) {
    *added = true;
  }
  return true;
}

static bool lr1_items_same_core(const LR1Item *a, const LR1Item *b) {
  return a->rule == b->rule && a->dot == b->dot;
}

static bool lr1_items_equal(const LR1Item *a, const LR1Item *b) {
  if (!lr1_items_same_core(a, b)) {
    return false;
  }
  if (a->lookahead.size != b->lookahead.size) {
    return false;
  }
  for (size_t i = 0; i < a->lookahead.size; ++i) {
    if (!string_vec_contains(&b->lookahead, a->lookahead.items[i])) {
      return false;
    }
  }
  return true;
}

static LR1State *lr1_state_create(void) {
  LR1State *state = calloc(1, sizeof(*state));
  if (!state) {
    return NULL;
  }
  ptr_vec_init(&state->items);
  ptr_vec_init(&state->transitions);
  return state;
}

static void lr1_transition_destroy(void *ptr);

static void lr1_state_destroy(void *ptr) {
  LR1State *state = ptr;
  if (!state) {
    return;
  }
  ptr_vec_free(&state->items, true, lr1_item_destroy);
  ptr_vec_free(&state->transitions, true, lr1_transition_destroy);
  free(state);
}

static bool lr1_state_add_item(LR1State *state, LR1Item *item) {
  return ptr_vec_push(&state->items, item);
}

static LR1Item *lr1_state_find_item(const LR1State *state, const Rule *rule,
                                    size_t dot) {
  for (size_t i = 0; i < state->items.size; ++i) {
    LR1Item *candidate = state->items.items[i];
    if (candidate->rule == rule && candidate->dot == dot) {
      return candidate;
    }
  }
  return NULL;
}

static bool lr1_states_same_core(const LR1State *a, const LR1State *b) {
  if (a->items.size != b->items.size) {
    return false;
  }
  for (size_t i = 0; i < a->items.size; ++i) {
    LR1Item *item_a = a->items.items[i];
    bool found = false;
    for (size_t j = 0; j < b->items.size; ++j) {
      LR1Item *item_b = b->items.items[j];
      if (lr1_items_same_core(item_a, item_b)) {
        found = true;
        break;
      }
    }
    if (!found) {
      return false;
    }
  }
  return true;
}

static bool lr1_states_equal(const LR1State *a, const LR1State *b) {
  if (a->items.size != b->items.size) {
    return false;
  }
  for (size_t i = 0; i < a->items.size; ++i) {
    LR1Item *item_a = a->items.items[i];
    bool found = false;
    for (size_t j = 0; j < b->items.size; ++j) {
      LR1Item *item_b = b->items.items[j];
      if (lr1_items_equal(item_a, item_b)) {
        found = true;
        break;
      }
    }
    if (!found) {
      return false;
    }
  }
  return true;
}

static LR1Transition *lr1_transition_create(const char *symbol,
                                            LR1State *state) {
  LR1Transition *transition = calloc(1, sizeof(*transition));
  if (!transition) {
    return NULL;
  }
  transition->symbol = symbol;
  transition->state = state;
  return transition;
}

static void lr1_transition_destroy(void *ptr) {
  LR1Transition *transition = ptr;
  if (!transition) {
    return;
  }
  free(transition);
}

static GoToNode *goto_node_create(const char *symbol, size_t state) {
  GoToNode *node = calloc(1, sizeof(*node));
  if (!node) {
    return NULL;
  }
  node->symbol = symbol;
  node->state = state;
  return node;
}

static void goto_node_destroy(void *ptr) {
  GoToNode *node = ptr;
  free(node);
}

static ActionEntry *action_entry_create(const char *terminal, ActionType type,
                                        size_t operand) {
  ActionEntry *entry = calloc(1, sizeof(*entry));
  if (!entry) {
    return NULL;
  }
  entry->terminal = terminal;
  entry->action.type = type;
  entry->action.operand = operand;
  return entry;
}

static void action_entry_destroy(void *ptr) {
  ActionEntry *entry = ptr;
  free(entry);
}

static LR1Parser *parser_create(Grammar *grammar, clexLexer *lexer,
                                const char *const *tokenKindStr) {
  LR1Parser *parser = calloc(1, sizeof(*parser));
  if (!parser) {
    return NULL;
  }
  parser->grammar = grammar;
  parser->lexer = lexer;
  parser->tokenKindStr = tokenKindStr;
  ptr_vec_init(&parser->collection);
  ptr_vec_init(&parser->goto_table);
  ptr_vec_init(&parser->action_table);
  return parser;
}

void cparseFreeParser(LR1Parser *parser) {
  if (!parser) {
    return;
  }
  ptr_vec_free(&parser->collection, true, lr1_state_destroy);
  for (size_t i = 0; i < parser->goto_table.size; ++i) {
    PtrVec *row = parser->goto_table.items[i];
    if (row) {
      ptr_vec_free(row, true, goto_node_destroy);
      free(row);
    }
  }
  ptr_vec_free(&parser->goto_table, false, NULL);
  for (size_t i = 0; i < parser->action_table.size; ++i) {
    PtrVec *row = parser->action_table.items[i];
    if (row) {
      ptr_vec_free(row, true, action_entry_destroy);
      free(row);
    }
  }
  ptr_vec_free(&parser->action_table, false, NULL);
  free(parser);
}

static PtrVec *ensure_row(PtrVec *table, size_t index) {
  while (table->size <= index) {
    PtrVec *row = calloc(1, sizeof(*row));
    if (!row) {
      return NULL;
    }
    ptr_vec_init(row);
    if (!ptr_vec_push(table, row)) {
      ptr_vec_free(row, false, NULL);
      free(row);
      return NULL;
    }
  }
  return table->items[index];
}

static ActionEntry *action_row_find(PtrVec *row, const char *terminal) {
  if (!row) {
    return NULL;
  }
  for (size_t i = 0; i < row->size; ++i) {
    ActionEntry *entry = row->items[i];
    if (strcmp(entry->terminal, terminal) == 0) {
      return entry;
    }
  }
  return NULL;
}

static bool add_action(LR1Parser *parser, size_t state, const char *terminal,
                       ActionType type, size_t operand) {
  PtrVec *row = ensure_row(&parser->action_table, state);
  if (!row) {
    return false;
  }
  ActionEntry *existing = action_row_find(row, terminal);
  if (existing) {
    if (existing->action.type != type || existing->action.operand != operand) {
      fprintf(stderr, "LR conflict on state %zu, terminal %s\n", state,
              terminal);
    }
    return true;
  }
  ActionEntry *entry = action_entry_create(terminal, type, operand);
  if (!entry) {
    return false;
  }
  if (!ptr_vec_push(row, entry)) {
    action_entry_destroy(entry);
    return false;
  }
  return true;
}

static GoToNode *goto_row_find(PtrVec *row, const char *symbol) {
  if (!row) {
    return NULL;
  }
  for (size_t i = 0; i < row->size; ++i) {
    GoToNode *node = row->items[i];
    if (strcmp(node->symbol, symbol) == 0) {
      return node;
    }
  }
  return NULL;
}

static bool add_goto(LR1Parser *parser, size_t state, const char *symbol,
                     size_t target) {
  PtrVec *row = ensure_row(&parser->goto_table, state);
  if (!row) {
    return false;
  }
  if (goto_row_find(row, symbol)) {
    return true;
  }
  GoToNode *node = goto_node_create(symbol, target);
  if (!node) {
    return false;
  }
  if (!ptr_vec_push(row, node)) {
    goto_node_destroy(node);
    return false;
  }
  return true;
}

static size_t parser_state_index(const LR1Parser *parser,
                                 const LR1State *state) {
  for (size_t i = 0; i < parser->collection.size; ++i) {
    if (parser->collection.items[i] == state) {
      return i;
    }
  }
  return (size_t)-1;
}

static bool parser_add_state(LR1Parser *parser, LR1State *state) {
  return ptr_vec_push(&parser->collection, state);
}

static LR1State *parser_find_state(const LR1Parser *parser,
                                   const LR1State *candidate,
                                   bool by_core_only) {
  for (size_t i = 0; i < parser->collection.size; ++i) {
    LR1State *existing = parser->collection.items[i];
    if (by_core_only ? lr1_states_same_core(existing, candidate)
                     : lr1_states_equal(existing, candidate)) {
      return existing;
    }
  }
  return NULL;
}

static const SymbolSetEntry *grammar_first_entry(const Grammar *grammar,
                                                 const char *symbol) {
  return symbol_set_find_const(&grammar->first, symbol);
}

static bool compute_first_sequence(const Grammar *grammar, const Rule *rule,
                                   size_t start_index,
                                   const StringVec *fallback,
                                   StringVec *output) {
  string_vec_init(output);
  bool add_fallback = true;
  if (start_index >= rule->right.size) {
    if (fallback) {
      if (!string_vec_extend_unique(output, fallback)) {
        return false;
      }
    }
    return true;
  }
  for (size_t i = start_index; i < rule->right.size; ++i) {
    const char *symbol = rule->right.items[i];
    if (strcmp(symbol, CPARSE_EPSILON) == 0) {
      continue;
    }
    if (grammar_is_terminal(grammar, symbol) ||
        !grammar_is_nonterminal(grammar, symbol)) {
      if (!string_vec_push_unique(output, (char *)symbol)) {
        return false;
      }
      add_fallback = false;
      break;
    }
    const SymbolSetEntry *first_entry = grammar_first_entry(grammar, symbol);
    if (!first_entry) {
      add_fallback = false;
      break;
    }
    bool epsilon_present = false;
    for (size_t j = 0; j < first_entry->values.size; ++j) {
      const char *candidate = first_entry->values.items[j];
      if (strcmp(candidate, CPARSE_EPSILON) == 0) {
        epsilon_present = true;
      } else if (!string_vec_push_unique(output, (char *)candidate)) {
        return false;
      }
    }
    if (!epsilon_present) {
      add_fallback = false;
      break;
    }
  }
  if (add_fallback && fallback) {
    if (!string_vec_extend_unique(output, fallback)) {
      return false;
    }
  }
  return true;
}

static bool closure(const Grammar *grammar, LR1State *state) {
  bool changed = true;
  while (changed) {
    changed = false;
    for (size_t i = 0; i < state->items.size; ++i) {
      LR1Item *item = state->items.items[i];
      size_t rhs_len = rule_symbol_count(item->rule);
      if (item->dot >= rhs_len) {
        continue;
      }
      const char *symbol = item->rule->right.items[item->dot];
      if (!grammar_is_nonterminal(grammar, symbol)) {
        continue;
      }
      StringVec lookahead;
      if (!compute_first_sequence(grammar, item->rule, item->dot + 1,
                                  &item->lookahead, &lookahead)) {
        return false;
      }
      for (size_t r = 0; r < grammar->rules.size; ++r) {
        Rule *candidate_rule = grammar->rules.items[r];
        if (strcmp(candidate_rule->left, symbol) != 0) {
          continue;
        }
        size_t initial_dot = rule_is_epsilon(candidate_rule)
                                 ? rule_symbol_count(candidate_rule)
                                 : 0;
        LR1Item *existing =
            lr1_state_find_item(state, candidate_rule, initial_dot);
        if (!existing) {
          LR1Item *new_item = lr1_item_create(candidate_rule, initial_dot);
          if (!new_item) {
            string_vec_free(&lookahead, false);
            return false;
          }
          if (!string_vec_extend_unique(&new_item->lookahead, &lookahead)) {
            lr1_item_destroy(new_item);
            string_vec_free(&lookahead, false);
            return false;
          }
          if (!lr1_state_add_item(state, new_item)) {
            lr1_item_destroy(new_item);
            string_vec_free(&lookahead, false);
            return false;
          }
          changed = true;
        } else {
          bool added = false;
          for (size_t j = 0; j < lookahead.size; ++j) {
            if (!lr1_item_add_lookahead(existing, lookahead.items[j], &added)) {
              string_vec_free(&lookahead, false);
              return false;
            }
          }
          if (added) {
            changed = true;
          }
        }
      }
      string_vec_free(&lookahead, false);
    }
  }
  return true;
}

static LR1State *goto_state(const Grammar *grammar, const LR1State *state,
                            const char *symbol) {
  LR1State *next = lr1_state_create();
  if (!next) {
    return NULL;
  }
  bool has_item = false;
  for (size_t i = 0; i < state->items.size; ++i) {
    LR1Item *item = state->items.items[i];
    size_t rhs_len = rule_symbol_count(item->rule);
    if (item->dot >= rhs_len) {
      continue;
    }
    const char *current = item->rule->right.items[item->dot];
    if (strcmp(current, symbol) != 0) {
      continue;
    }
    LR1Item *advanced = lr1_item_create(item->rule, item->dot + 1);
    if (!advanced) {
      lr1_state_destroy(next);
      return NULL;
    }
    if (!string_vec_extend_unique(&advanced->lookahead, &item->lookahead)) {
      lr1_item_destroy(advanced);
      lr1_state_destroy(next);
      return NULL;
    }
    if (!lr1_state_add_item(next, advanced)) {
      lr1_item_destroy(advanced);
      lr1_state_destroy(next);
      return NULL;
    }
    has_item = true;
  }
  if (!has_item) {
    lr1_state_destroy(next);
    return NULL;
  }
  if (!closure(grammar, next)) {
    lr1_state_destroy(next);
    return NULL;
  }
  return next;
}

static bool build_lr1_collection(LR1Parser *parser) {
  Rule *start_rule = parser->grammar->rules.items[0];
  LR1Item *start_item = lr1_item_create(start_rule, 0);
  if (!start_item) {
    return false;
  }
  if (!lr1_item_add_lookahead(start_item, kEndMarker, NULL)) {
    lr1_item_destroy(start_item);
    return false;
  }
  LR1State *start_state = lr1_state_create();
  if (!start_state) {
    lr1_item_destroy(start_item);
    return false;
  }
  if (!lr1_state_add_item(start_state, start_item)) {
    lr1_item_destroy(start_item);
    lr1_state_destroy(start_state);
    return false;
  }
  if (!closure(parser->grammar, start_state)) {
    lr1_state_destroy(start_state);
    return false;
  }
  if (!parser_add_state(parser, start_state)) {
    lr1_state_destroy(start_state);
    return false;
  }
  for (size_t i = 0; i < parser->collection.size; ++i) {
    LR1State *state = parser->collection.items[i];
    StringVec symbols;
    string_vec_init(&symbols);
    for (size_t j = 0; j < state->items.size; ++j) {
      LR1Item *item = state->items.items[j];
      size_t rhs_len = rule_symbol_count(item->rule);
      if (item->dot >= rhs_len) {
        continue;
      }
      const char *symbol = item->rule->right.items[item->dot];
      if (strcmp(symbol, CPARSE_EPSILON) == 0) {
        continue;
      }
      string_vec_push_unique(&symbols, (char *)symbol);
    }
    for (size_t s = 0; s < symbols.size; ++s) {
      LR1State *next = goto_state(parser->grammar, state, symbols.items[s]);
      if (!next) {
        continue;
      }
      LR1State *existing = parser_find_state(parser, next, false);
      if (!existing) {
        if (!parser_add_state(parser, next)) {
          lr1_state_destroy(next);
          string_vec_free(&symbols, false);
          return false;
        }
        existing = next;
      } else {
        lr1_state_destroy(next);
      }
      LR1Transition *transition =
          lr1_transition_create(symbols.items[s], existing);
      if (!transition) {
        string_vec_free(&symbols, false);
        return false;
      }
      if (!ptr_vec_push(&state->transitions, transition)) {
        lr1_transition_destroy(transition);
        string_vec_free(&symbols, false);
        return false;
      }
    }
    string_vec_free(&symbols, false);
  }
  return true;
}

static LR1Item *lr1_item_clone_core(const LR1Item *item) {
  LR1Item *clone = lr1_item_create(item->rule, item->dot);
  if (!clone) {
    return NULL;
  }
  return clone;
}

static LR1State *lr1_state_clone_core(const LR1State *state) {
  LR1State *clone = lr1_state_create();
  if (!clone) {
    return NULL;
  }
  for (size_t i = 0; i < state->items.size; ++i) {
    LR1Item *item = lr1_item_clone_core(state->items.items[i]);
    if (!item) {
      lr1_state_destroy(clone);
      return NULL;
    }
    if (!lr1_state_add_item(clone, item)) {
      lr1_item_destroy(item);
      lr1_state_destroy(clone);
      return NULL;
    }
  }
  return clone;
}

static bool merge_states_into(LR1State *target, const LR1State *source) {
  for (size_t i = 0; i < source->items.size; ++i) {
    LR1Item *source_item = source->items.items[i];
    LR1Item *target_item =
        lr1_state_find_item(target, source_item->rule, source_item->dot);
    if (!target_item) {
      LR1Item *clone = lr1_item_clone_core(source_item);
      if (!clone) {
        return false;
      }
      if (!string_vec_extend_unique(&clone->lookahead,
                                    &source_item->lookahead)) {
        lr1_item_destroy(clone);
        return false;
      }
      if (!lr1_state_add_item(target, clone)) {
        lr1_item_destroy(clone);
        return false;
      }
    } else {
      if (!string_vec_extend_unique(&target_item->lookahead,
                                    &source_item->lookahead)) {
        return false;
      }
    }
  }
  return true;
}

static bool build_lalr_collection(LR1Parser *parser) {
  LR1Parser *lr1_parser =
      parser_create(parser->grammar, parser->lexer, parser->tokenKindStr);
  if (!lr1_parser) {
    return false;
  }
  if (!build_lr1_collection(lr1_parser)) {
    cparseFreeParser(lr1_parser);
    return false;
  }
  PtrVec state_map;
  ptr_vec_init(&state_map);
  if (!ptr_vec_reserve(&state_map, lr1_parser->collection.size)) {
    ptr_vec_free(&state_map, false, NULL);
    cparseFreeParser(lr1_parser);
    return false;
  }
  for (size_t i = 0; i < lr1_parser->collection.size; ++i) {
    LR1State *source = lr1_parser->collection.items[i];
    LR1State *existing = parser_find_state(parser, source, true);
    bool new_state_created = false;
    if (!existing) {
      existing = lr1_state_clone_core(source);
      if (!existing) {
        ptr_vec_free(&state_map, false, NULL);
        cparseFreeParser(lr1_parser);
        return false;
      }
      if (!parser_add_state(parser, existing)) {
        lr1_state_destroy(existing);
        ptr_vec_free(&state_map, false, NULL);
        cparseFreeParser(lr1_parser);
        return false;
      }
      new_state_created = true;
    }
    if (!merge_states_into(existing, source)) {
      ptr_vec_free(&state_map, false, NULL);
      cparseFreeParser(lr1_parser);
      return false;
    }
    if (!ptr_vec_push(&state_map, existing)) {
      ptr_vec_free(&state_map, false, NULL);
      cparseFreeParser(lr1_parser);
      return false;
    }
    if (new_state_created) {
      ptr_vec_init(&existing->transitions);
    }
  }
  for (size_t i = 0; i < lr1_parser->collection.size; ++i) {
    LR1State *source = lr1_parser->collection.items[i];
    LR1State *source_mapped = state_map.items[i];
    for (size_t t = 0; t < source->transitions.size; ++t) {
      LR1Transition *transition = source->transitions.items[t];
      size_t target_index = parser_state_index(lr1_parser, transition->state);
      LR1State *mapped_target = state_map.items[target_index];
      bool exists = false;
      for (size_t existing_index = 0;
           existing_index < source_mapped->transitions.size; ++existing_index) {
        LR1Transition *existing_transition =
            source_mapped->transitions.items[existing_index];
        if (strcmp(existing_transition->symbol, transition->symbol) == 0 &&
            existing_transition->state == mapped_target) {
          exists = true;
          break;
        }
      }
      if (!exists) {
        LR1Transition *new_transition =
            lr1_transition_create(transition->symbol, mapped_target);
        if (!new_transition) {
          ptr_vec_free(&state_map, false, NULL);
          cparseFreeParser(lr1_parser);
          return false;
        }
        if (!ptr_vec_push(&source_mapped->transitions, new_transition)) {
          lr1_transition_destroy(new_transition);
          ptr_vec_free(&state_map, false, NULL);
          cparseFreeParser(lr1_parser);
          return false;
        }
      }
    }
  }
  ptr_vec_free(&state_map, false, NULL);
  cparseFreeParser(lr1_parser);
  return true;
}

static ssize_t grammar_rule_index(const Grammar *grammar, const Rule *rule) {
  for (size_t i = 0; i < grammar->rules.size; ++i) {
    if (grammar->rules.items[i] == rule) {
      return (ssize_t)i;
    }
  }
  return -1;
}

static bool build_tables(LR1Parser *parser) {
  for (size_t i = 0; i < parser->collection.size; ++i) {
    LR1State *state = parser->collection.items[i];
    for (size_t t = 0; t < state->transitions.size; ++t) {
      LR1Transition *transition = state->transitions.items[t];
      size_t target_index = parser_state_index(parser, transition->state);
      if (grammar_is_nonterminal(parser->grammar, transition->symbol)) {
        if (!add_goto(parser, i, transition->symbol, target_index)) {
          return false;
        }
      } else {
        if (!add_action(parser, i, transition->symbol, ACTION_SHIFT,
                        target_index)) {
          return false;
        }
      }
    }
    for (size_t item_index = 0; item_index < state->items.size; ++item_index) {
      LR1Item *item = state->items.items[item_index];
      size_t rhs_len = rule_symbol_count(item->rule);
      if (item->dot < rhs_len) {
        continue;
      }
      if (strcmp(item->rule->left, CPARSE_START_SYMBOL) == 0) {
        if (!add_action(parser, i, kEndMarker, ACTION_ACCEPT, 0)) {
          return false;
        }
        continue;
      }
      ssize_t rule_index = grammar_rule_index(parser->grammar, item->rule);
      if (rule_index < 0) {
        return false;
      }
      for (size_t la = 0; la < item->lookahead.size; ++la) {
        if (!add_action(parser, i, item->lookahead.items[la], ACTION_REDUCE,
                        (size_t)rule_index)) {
          return false;
        }
      }
    }
  }
  return true;
}

LR1Parser *cparseCreateLR1Parser(Grammar *grammar, clexLexer *lexer,
                                 const char *const *tokenKindStr) {
  LR1Parser *parser = parser_create(grammar, lexer, tokenKindStr);
  if (!parser) {
    return NULL;
  }
  if (!build_lr1_collection(parser)) {
    cparseFreeParser(parser);
    return NULL;
  }
  if (!build_tables(parser)) {
    cparseFreeParser(parser);
    return NULL;
  }
  return parser;
}

LALR1Parser *cparseCreateLALR1Parser(Grammar *grammar, clexLexer *lexer,
                                     const char *const *tokenKindStr) {
  LR1Parser *parser = parser_create(grammar, lexer, tokenKindStr);
  if (!parser) {
    return NULL;
  }
  if (!build_lalr_collection(parser)) {
    cparseFreeParser(parser);
    return NULL;
  }
  if (!build_tables(parser)) {
    cparseFreeParser(parser);
    return NULL;
  }
  return parser;
}

static ActionEntry *parser_get_action(const LR1Parser *parser, size_t state,
                                      const char *terminal) {
  if (state >= parser->action_table.size) {
    return NULL;
  }
  PtrVec *row = parser->action_table.items[state];
  return action_row_find(row, terminal);
}

static ssize_t parser_goto_state(const LR1Parser *parser, size_t state,
                                 const char *symbol) {
  if (state >= parser->goto_table.size) {
    return -1;
  }
  PtrVec *row = parser->goto_table.items[state];
  GoToNode *node = goto_row_find(row, symbol);
  if (!node) {
    return -1;
  }
  return (ssize_t)node->state;
}

typedef struct {
  size_t *data;
  size_t size;
  size_t capacity;
} SizeTStack;

static void stack_init(SizeTStack *stack) {
  stack->data = NULL;
  stack->size = 0;
  stack->capacity = 0;
}

static void stack_free(SizeTStack *stack) {
  free(stack->data);
  stack->data = NULL;
  stack->size = stack->capacity = 0;
}

static bool stack_reserve(SizeTStack *stack, size_t capacity) {
  if (stack->capacity >= capacity) {
    return true;
  }
  size_t new_capacity = stack->capacity ? stack->capacity : 8;
  while (new_capacity < capacity) {
    new_capacity *= 2;
  }
  size_t *values = realloc(stack->data, new_capacity * sizeof(size_t));
  if (!values) {
    return false;
  }
  stack->data = values;
  stack->capacity = new_capacity;
  return true;
}

static bool stack_push(SizeTStack *stack, size_t value) {
  if (!stack_reserve(stack, stack->size + 1)) {
    return false;
  }
  stack->data[stack->size++] = value;
  return true;
}

static bool stack_pop(SizeTStack *stack, size_t *value) {
  if (stack->size == 0) {
    return false;
  }
  if (value) {
    *value = stack->data[stack->size - 1];
  }
  stack->size--;
  return true;
}

static size_t stack_top(const SizeTStack *stack) {
  assert(stack->size > 0);
  return stack->data[stack->size - 1];
}

static bool ptr_vec_push_ptr(PtrVec *vec, void *value) {
  return ptr_vec_push(vec, value);
}

static void *ptr_vec_pop_ptr(PtrVec *vec) {
  if (vec->size == 0) {
    return NULL;
  }
  void *value = vec->items[vec->size - 1];
  vec->size--;
  return value;
}

static ParseTreeNode *parse_tree_node_create(const char *value) {
  ParseTreeNode *node = calloc(1, sizeof(*node));
  if (!node) {
    return NULL;
  }
  node->value = (char *)value;
  ptr_vec_init(&node->children);
  node->token.kind = -1;
  node->token.lexeme = NULL;
  return node;
}

static ParseTreeNode *parse_tree_node_create_with_token(const char *value,
                                                        clexToken token) {
  ParseTreeNode *node = parse_tree_node_create(value);
  if (!node) {
    return NULL;
  }
  node->token = token;
  return node;
}

void cparseFreeParseTree(ParseTreeNode *node) {
  if (!node) {
    return;
  }
  for (size_t i = 0; i < node->children.size; ++i) {
    cparseFreeParseTree(node->children.items[i]);
  }
  ptr_vec_free(&node->children, false, NULL);
  free_token(&node->token);
  free(node);
}

static bool accept_or_parse(LR1Parser *parser, const char *input,
                            bool build_tree, ParseTreeNode **out_tree,
                            bool *accepted) {
  if (!parser || !parser->lexer) {
    return false;
  }

  clexReset(parser->lexer, input);
  bool lex_next = true;
  clexToken token = {.kind = -1, .lexeme = NULL};

  SizeTStack state_stack;
  stack_init(&state_stack);
  if (!stack_push(&state_stack, 0)) {
    stack_free(&state_stack);
    return false;
  }

  PtrVec symbol_stack;
  ptr_vec_init(&symbol_stack);

  PtrVec node_stack;
  if (build_tree) {
    ptr_vec_init(&node_stack);
  }

  bool success = false;
  while (true) {
    if (lex_next) {
      free_token(&token);
      token = clex(parser->lexer);
    }
    lex_next = true;
    const char *terminal =
        token.kind >= 0 ? parser->tokenKindStr[token.kind] : kEndMarker;
    size_t current_state = stack_top(&state_stack);
    ActionEntry *action = parser_get_action(parser, current_state, terminal);
    if (!action) {
      success = false;
      break;
    }
    if (action->action.type == ACTION_SHIFT) {
      if (!ptr_vec_push_ptr(&symbol_stack, (void *)terminal)) {
        success = false;
        break;
      }
      if (!stack_push(&state_stack, action->action.operand)) {
        success = false;
        break;
      }
      if (build_tree) {
        ParseTreeNode *leaf =
            parse_tree_node_create_with_token(terminal, token);
        if (!leaf || !ptr_vec_push_ptr(&node_stack, leaf)) {
          if (leaf) {
            cparseFreeParseTree(leaf);
          }
          success = false;
          break;
        }
        token.lexeme = NULL;
      } else {
        free_token(&token);
      }
    } else if (action->action.type == ACTION_REDUCE) {
      Rule *rule = parser->grammar->rules.items[action->action.operand];
      size_t rhs_len = rule_symbol_count(rule);
      PtrVec children;
      if (build_tree) {
        ptr_vec_init(&children);
      }
      for (size_t i = 0; i < rhs_len; ++i) {
        ptr_vec_pop_ptr(&symbol_stack);
        stack_pop(&state_stack, NULL);
        if (build_tree) {
          ParseTreeNode *child = ptr_vec_pop_ptr(&node_stack);
          ptr_vec_push_ptr(&children, child);
        }
      }
      size_t next_state_index = stack_top(&state_stack);
      ssize_t goto_state_value =
          parser_goto_state(parser, next_state_index, rule->left);
      if (goto_state_value < 0) {
        if (build_tree) {
          for (size_t i = 0; i < children.size; ++i) {
            cparseFreeParseTree(children.items[i]);
          }
          ptr_vec_free(&children, false, NULL);
        }
        success = false;
        break;
      }
      if (!ptr_vec_push_ptr(&symbol_stack, rule->left)) {
        if (build_tree) {
          for (size_t i = 0; i < children.size; ++i) {
            cparseFreeParseTree(children.items[i]);
          }
          ptr_vec_free(&children, false, NULL);
        }
        success = false;
        break;
      }
      if (!stack_push(&state_stack, (size_t)goto_state_value)) {
        if (build_tree) {
          for (size_t i = 0; i < children.size; ++i) {
            cparseFreeParseTree(children.items[i]);
          }
          ptr_vec_free(&children, false, NULL);
        }
        success = false;
        break;
      }
      lex_next = false;
      if (build_tree) {
        ParseTreeNode *parent = parse_tree_node_create(rule->left);
        if (!parent) {
          for (size_t i = 0; i < children.size; ++i) {
            cparseFreeParseTree(children.items[i]);
          }
          ptr_vec_free(&children, false, NULL);
          success = false;
          break;
        }
        for (size_t i = children.size; i > 0; --i) {
          ptr_vec_push_ptr(&parent->children, children.items[i - 1]);
        }
        ptr_vec_free(&children, false, NULL);
        if (!ptr_vec_push_ptr(&node_stack, parent)) {
          cparseFreeParseTree(parent);
          success = false;
          break;
        }
      }
    } else if (action->action.type == ACTION_ACCEPT) {
      success = true;
      break;
    }
  }

  bool accepted_value = success;
  if (accepted) {
    *accepted = accepted_value;
  }

  if (!success || !accepted_value) {
    free_token(&token);
    if (build_tree) {
      while (node_stack.size > 0) {
        ParseTreeNode *node = ptr_vec_pop_ptr(&node_stack);
        cparseFreeParseTree(node);
      }
      ptr_vec_free(&node_stack, false, NULL);
    }
    ptr_vec_free(&symbol_stack, false, NULL);
    stack_free(&state_stack);
    return false;
  }

  if (build_tree) {
    ParseTreeNode *root =
        node_stack.size > 0 ? node_stack.items[node_stack.size - 1] : NULL;
    if (out_tree) {
      *out_tree = root;
    } else {
      cparseFreeParseTree(root);
    }
    ptr_vec_free(&node_stack, false, NULL);
  }
  free_token(&token);
  ptr_vec_free(&symbol_stack, false, NULL);
  stack_free(&state_stack);
  return true;
}

bool cparseAccept(LR1Parser *parser, const char *input) {
  bool accepted = false;
  if (!accept_or_parse(parser, input, false, NULL, &accepted)) {
    return false;
  }
  return accepted;
}

ParseTreeNode *cparse(LR1Parser *parser, const char *input) {
  ParseTreeNode *tree = NULL;
  bool accepted = false;
  if (!accept_or_parse(parser, input, true, &tree, &accepted) || !accepted) {
    cparseFreeParseTree(tree);
    return NULL;
  }
  return tree;
}

typedef struct {
  char *data;
  size_t size;
  size_t capacity;
} StringBuilder;

static bool sb_init(StringBuilder *sb, size_t capacity) {
  sb->data = malloc(capacity);
  if (!sb->data) {
    sb->size = sb->capacity = 0;
    return false;
  }
  sb->data[0] = '\0';
  sb->size = 0;
  sb->capacity = capacity;
  return true;
}

static bool sb_reserve(StringBuilder *sb, size_t additional) {
  size_t required = sb->size + additional + 1;
  if (required <= sb->capacity) {
    return true;
  }
  size_t new_capacity = sb->capacity ? sb->capacity : 128;
  while (new_capacity < required) {
    new_capacity *= 2;
  }
  char *data = realloc(sb->data, new_capacity);
  if (!data) {
    return false;
  }
  sb->data = data;
  sb->capacity = new_capacity;
  return true;
}

static bool sb_append(StringBuilder *sb, const char *text) {
  size_t len = strlen(text);
  if (!sb_reserve(sb, len)) {
    return false;
  }
  memcpy(sb->data + sb->size, text, len);
  sb->size += len;
  sb->data[sb->size] = '\0';
  return true;
}

static bool sb_append_int(StringBuilder *sb, size_t value) {
  char buffer[32];
  snprintf(buffer, sizeof(buffer), "%zu", value);
  return sb_append(sb, buffer);
}

char *getLR1ParserAsString(LR1Parser *parser) {
  if (!parser) {
    return NULL;
  }
  StringBuilder sb;
  if (!sb_init(&sb, 256)) {
    return NULL;
  }
  sb_append(&sb, "States:\n");
  for (size_t i = 0; i < parser->collection.size; ++i) {
    LR1State *state = parser->collection.items[i];
    sb_append(&sb, "State ");
    sb_append_int(&sb, i);
    sb_append(&sb, ":\n");
    for (size_t j = 0; j < state->items.size; ++j) {
      LR1Item *item = state->items.items[j];
      sb_append(&sb, "  ");
      sb_append(&sb, item->rule->left);
      sb_append(&sb, " -> ");
      for (size_t r = 0; r < item->rule->right.size; ++r) {
        if (r == item->dot) {
          sb_append(&sb, "• ");
        }
        sb_append(&sb, item->rule->right.items[r]);
        sb_append(&sb, " ");
      }
      if (item->dot >= item->rule->right.size) {
        sb_append(&sb, "• ");
      }
      sb_append(&sb, "[ ");
      for (size_t la = 0; la < item->lookahead.size; ++la) {
        if (la > 0) {
          sb_append(&sb, ", ");
        }
        sb_append(&sb, item->lookahead.items[la]);
      }
      sb_append(&sb, " ]\n");
    }
    if (state->transitions.size > 0) {
      sb_append(&sb, "  Transitions:\n");
      for (size_t t = 0; t < state->transitions.size; ++t) {
        LR1Transition *transition = state->transitions.items[t];
        sb_append(&sb, "    ");
        sb_append(&sb, transition->symbol);
        sb_append(&sb, " -> ");
        sb_append_int(&sb, parser_state_index(parser, transition->state));
        sb_append(&sb, "\n");
      }
    }
  }
  sb_append(&sb, "Goto table:\n");
  for (size_t i = 0; i < parser->goto_table.size; ++i) {
    PtrVec *row = parser->goto_table.items[i];
    if (!row || row->size == 0) {
      continue;
    }
    for (size_t j = 0; j < row->size; ++j) {
      GoToNode *node = row->items[j];
      sb_append(&sb, "  ");
      sb_append_int(&sb, i);
      sb_append(&sb, " ");
      sb_append(&sb, node->symbol);
      sb_append(&sb, " -> ");
      sb_append_int(&sb, node->state);
      sb_append(&sb, "\n");
    }
  }
  sb_append(&sb, "Action table:\n");
  for (size_t i = 0; i < parser->action_table.size; ++i) {
    PtrVec *row = parser->action_table.items[i];
    if (!row || row->size == 0) {
      continue;
    }
    for (size_t j = 0; j < row->size; ++j) {
      ActionEntry *entry = row->items[j];
      sb_append(&sb, "  ");
      sb_append_int(&sb, i);
      sb_append(&sb, " ");
      sb_append(&sb, entry->terminal);
      sb_append(&sb, " -> ");
      sb_append_int(&sb, entry->action.type);
      sb_append(&sb, " ");
      sb_append_int(&sb, entry->action.operand);
      sb_append(&sb, "\n");
    }
  }
  return sb.data;
}

char *getParseTreeAsString(ParseTreeNode *root) {
  if (!root) {
    return cparse_strdup("");
  }
  StringBuilder sb;
  if (!sb_init(&sb, 128)) {
    return NULL;
  }
  PtrVec stack;
  ptr_vec_init(&stack);
  ptr_vec_push_ptr(&stack, root);
  while (stack.size > 0) {
    ParseTreeNode *node = ptr_vec_pop_ptr(&stack);
    sb_append(&sb, node->value);
    sb_append(&sb, " ");
    sb_append(&sb, node->token.lexeme ? node->token.lexeme : "");
    sb_append(&sb, "\n");
    for (size_t i = node->children.size; i > 0; --i) {
      ptr_vec_push_ptr(&stack, node->children.items[i - 1]);
    }
  }
  ptr_vec_free(&stack, false, NULL);
  return sb.data;
}

#include "lr1_lalr1.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clex/clex.h"
#include "cparse.h"

static const char* kEndMarker = "$";

static clexSourcePosition make_position(size_t offset, size_t line,
                                        size_t column) {
  clexSourcePosition position;
  position.offset = offset;
  position.line = line;
  position.column = column;
  return position;
}

static void cparse_error_init(cparseError* error) {
  if (!error) {
    return;
  }
  error->status = CPARSE_STATUS_OK;
  error->position = make_position(0, 1, 1);
  error->offending_lexeme = NULL;
  string_vec_init(&error->expected_tokens);
  error->offending_token_kind = CLEX_TOKEN_EOF;
  error->parser_state = 0;
}

void cparseClearError(cparseError* error) {
  if (!error) {
    return;
  }
  free(error->offending_lexeme);
  error->offending_lexeme = NULL;
  string_vec_free(&error->expected_tokens, true);
  string_vec_init(&error->expected_tokens);
  error->status = CPARSE_STATUS_OK;
  error->position = make_position(0, 1, 1);
  error->offending_token_kind = CLEX_TOKEN_EOF;
  error->parser_state = 0;
}

const cparseError* cparseGetLastError(const LR1Parser* parser) {
  if (!parser) {
    return NULL;
  }
  return &parser->last_error;
}

static bool cparse_error_set_offending_lexeme(cparseError* error,
                                              const char* lexeme) {
  if (!error) {
    return true;
  }
  free(error->offending_lexeme);
  error->offending_lexeme = NULL;
  if (!lexeme) {
    return true;
  }
  error->offending_lexeme = cparse_strdup(lexeme);
  return error->offending_lexeme != NULL;
}

static bool cparse_error_add_expected(cparseError* error,
                                      const char* expected_token) {
  if (!error || !expected_token) {
    return true;
  }
  return string_vec_push_unique_copy(&error->expected_tokens, expected_token);
}

static bool cparse_error_fill_expected_for_state(const LR1Parser* parser,
                                                 size_t state,
                                                 cparseError* error) {
  if (!parser || !error || state >= parser->state_count) {
    return true;
  }
  for (size_t i = 0; i < parser->terminal_count; ++i) {
    size_t index = state * parser->terminal_count + i;
    if (!parser->action_present || !parser->action_present[index]) {
      continue;
    }
    const ActionEntry* entry = &parser->action_table[index];
    const char* expected =
        strcmp(entry->terminal, kEndMarker) == 0 ? "EOF" : entry->terminal;
    if (!cparse_error_add_expected(error, expected)) {
      return false;
    }
  }
  return true;
}

static void free_token(clexToken* token) {
  if (!token) {
    return;
  }
  clexTokenClear(token);
}

static bool grammar_is_terminal(const Grammar* grammar, const char* symbol) {
  if (!symbol || strcmp(symbol, CPARSE_EPSILON) == 0) {
    return false;
  }
  return string_vec_contains(&grammar->terminals, symbol) &&
         !string_vec_contains(&grammar->nonterminals, symbol);
}

static bool grammar_is_nonterminal(const Grammar* grammar, const char* symbol) {
  return string_vec_contains(&grammar->nonterminals, symbol);
}

static bool rule_is_epsilon(const Rule* rule) {
  return rule->right.size == 1 &&
         strcmp(rule->right.items[0], CPARSE_EPSILON) == 0;
}

static size_t rule_symbol_count(const Rule* rule) {
  return rule_is_epsilon(rule) ? 0 : rule->right.size;
}

static LR1Item* lr1_item_create(Rule* rule, size_t dot) {
  LR1Item* item = calloc(1, sizeof(*item));
  if (!item) {
    return NULL;
  }
  item->rule = rule;
  item->dot = dot;
  string_vec_init(&item->lookahead);
  return item;
}

static void lr1_item_destroy(void* ptr) {
  LR1Item* item = ptr;
  if (!item) {
    return;
  }
  string_vec_free(&item->lookahead, false);
  free(item);
}

static bool lr1_item_add_lookahead(LR1Item* item, const char* terminal,
                                   bool* added) {
  size_t before = item->lookahead.size;
  if (!string_vec_push_unique(&item->lookahead, (char*)terminal)) {
    return false;
  }
  if (added && item->lookahead.size != before) {
    *added = true;
  }
  return true;
}

static bool lr1_items_same_core(const LR1Item* a, const LR1Item* b) {
  return a->rule == b->rule && a->dot == b->dot;
}

static bool lr1_items_equal(const LR1Item* a, const LR1Item* b) {
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

static LR1State* lr1_state_create(void) {
  LR1State* state = calloc(1, sizeof(*state));
  if (!state) {
    return NULL;
  }
  ptr_vec_init(&state->items);
  ptr_vec_init(&state->transitions);
  return state;
}

static void lr1_transition_destroy(void* ptr);

static void lr1_state_destroy(void* ptr) {
  LR1State* state = ptr;
  if (!state) {
    return;
  }
  ptr_vec_free(&state->items, true, lr1_item_destroy);
  ptr_vec_free(&state->transitions, true, lr1_transition_destroy);
  free(state);
}

static bool lr1_state_add_item(LR1State* state, LR1Item* item) {
  return ptr_vec_push(&state->items, item);
}

static LR1Item* lr1_state_find_item(const LR1State* state, const Rule* rule,
                                    size_t dot) {
  for (size_t i = 0; i < state->items.size; ++i) {
    LR1Item* candidate = state->items.items[i];
    if (candidate->rule == rule && candidate->dot == dot) {
      return candidate;
    }
  }
  return NULL;
}

static bool lr1_states_same_core(const LR1State* a, const LR1State* b) {
  if (a->items.size != b->items.size) {
    return false;
  }
  for (size_t i = 0; i < a->items.size; ++i) {
    LR1Item* item_a = a->items.items[i];
    bool found = false;
    for (size_t j = 0; j < b->items.size; ++j) {
      LR1Item* item_b = b->items.items[j];
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

static bool lr1_states_equal(const LR1State* a, const LR1State* b) {
  if (a->items.size != b->items.size) {
    return false;
  }
  for (size_t i = 0; i < a->items.size; ++i) {
    LR1Item* item_a = a->items.items[i];
    bool found = false;
    for (size_t j = 0; j < b->items.size; ++j) {
      LR1Item* item_b = b->items.items[j];
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

static LR1Transition* lr1_transition_create(const char* symbol,
                                            LR1State* state) {
  LR1Transition* transition = calloc(1, sizeof(*transition));
  if (!transition) {
    return NULL;
  }
  transition->symbol = symbol;
  transition->state = state;
  return transition;
}

static void lr1_transition_destroy(void* ptr) {
  LR1Transition* transition = ptr;
  if (!transition) {
    return;
  }
  free(transition);
}

static bool parser_init_symbol_maps(LR1Parser* parser);

static LR1Parser* parser_create(Grammar* grammar, clexLexer* lexer,
                                const char* const* tokenKindStr,
                                size_t tokenKindCount) {
  LR1Parser* parser = calloc(1, sizeof(*parser));
  if (!parser) {
    return NULL;
  }
  parser->grammar = grammar;
  parser->lexer = lexer;
  parser->tokenKindStr = tokenKindStr;
  parser->tokenKindCount = tokenKindCount;
  ptr_vec_init(&parser->collection);
  cparse_error_init(&parser->last_error);
  if (!parser_init_symbol_maps(parser)) {
    cparseFreeParser(parser);
    return NULL;
  }
  return parser;
}

void cparseFreeParser(LR1Parser* parser) {
  if (!parser) {
    return;
  }
  ptr_vec_free(&parser->collection, true, lr1_state_destroy);
  free(parser->terminal_symbols);
  free(parser->nonterminal_symbols);
  free(parser->token_kind_to_terminal);
  free(parser->rule_nonterminal_ids);
  free(parser->goto_table);
  free(parser->action_table);
  free(parser->action_present);
  cparseClearError(&parser->last_error);
  free(parser);
}

static bool safe_mul(size_t a, size_t b, size_t* out) {
  if (!out) {
    return false;
  }
  if (a == 0 || b == 0) {
    *out = 0;
    return true;
  }
  if (a > (size_t)-1 / b) {
    return false;
  }
  *out = a * b;
  return true;
}

static size_t action_table_index(const LR1Parser* parser, size_t state,
                                 size_t terminal_id) {
  return state * parser->terminal_count + terminal_id;
}

static size_t goto_table_index(const LR1Parser* parser, size_t state,
                               size_t nonterminal_id) {
  return state * parser->nonterminal_count + nonterminal_id;
}

static ptrdiff_t parser_terminal_id(const LR1Parser* parser,
                                    const char* terminal) {
  if (!parser || !terminal) {
    return -1;
  }
  for (size_t i = 0; i < parser->terminal_count; ++i) {
    const char* candidate = parser->terminal_symbols[i];
    if (candidate && strcmp(candidate, terminal) == 0) {
      return (ptrdiff_t)i;
    }
  }
  return -1;
}

static ptrdiff_t parser_nonterminal_id(const LR1Parser* parser,
                                       const char* nonterminal) {
  if (!parser || !nonterminal) {
    return -1;
  }
  for (size_t i = 0; i < parser->nonterminal_count; ++i) {
    const char* candidate = parser->nonterminal_symbols[i];
    if (candidate && strcmp(candidate, nonterminal) == 0) {
      return (ptrdiff_t)i;
    }
  }
  return -1;
}

static bool symbol_array_contains(const char* const* symbols, size_t count,
                                  const char* symbol) {
  if (!symbols || !symbol) {
    return false;
  }
  for (size_t i = 0; i < count; ++i) {
    if (symbols[i] && strcmp(symbols[i], symbol) == 0) {
      return true;
    }
  }
  return false;
}

static bool parser_init_symbol_maps(LR1Parser* parser) {
  if (!parser || !parser->grammar) {
    return false;
  }

  size_t extra_terminals = 0;
  for (size_t i = 0; i < parser->tokenKindCount; ++i) {
    if (!parser->tokenKindStr || !parser->tokenKindStr[i]) {
      continue;
    }
    const char* token_name = parser->tokenKindStr[i];
    if (string_vec_contains(&parser->grammar->terminals, token_name)) {
      continue;
    }
    bool already_counted = false;
    for (size_t j = 0; j < i; ++j) {
      if (parser->tokenKindStr && parser->tokenKindStr[j] &&
          strcmp(parser->tokenKindStr[j], token_name) == 0) {
        already_counted = true;
        break;
      }
    }
    if (!already_counted) {
      extra_terminals++;
    }
  }

  parser->terminal_count =
      parser->grammar->terminals.size + extra_terminals + 1;
  parser->nonterminal_count = parser->grammar->nonterminals.size;

  parser->terminal_symbols = calloc(parser->terminal_count, sizeof(char*));
  parser->nonterminal_symbols =
      calloc(parser->nonterminal_count, sizeof(char*));
  if ((parser->terminal_count > 0 && !parser->terminal_symbols) ||
      (parser->nonterminal_count > 0 && !parser->nonterminal_symbols)) {
    return false;
  }

  size_t terminal_write_index = 0;
  for (size_t i = 0; i < parser->grammar->terminals.size; ++i) {
    parser->terminal_symbols[terminal_write_index++] =
        parser->grammar->terminals.items[i];
  }
  for (size_t i = 0; i < parser->tokenKindCount; ++i) {
    if (!parser->tokenKindStr || !parser->tokenKindStr[i]) {
      continue;
    }
    const char* token_name = parser->tokenKindStr[i];
    if (symbol_array_contains(parser->terminal_symbols, terminal_write_index,
                              token_name)) {
      continue;
    }
    parser->terminal_symbols[terminal_write_index++] = token_name;
  }
  parser->terminal_symbols[terminal_write_index++] = kEndMarker;
  if (terminal_write_index != parser->terminal_count) {
    return false;
  }

  for (size_t i = 0; i < parser->grammar->nonterminals.size; ++i) {
    parser->nonterminal_symbols[i] = parser->grammar->nonterminals.items[i];
  }

  if (parser->tokenKindCount > 0) {
    parser->token_kind_to_terminal =
        malloc(parser->tokenKindCount * sizeof(ptrdiff_t));
    if (!parser->token_kind_to_terminal) {
      return false;
    }
    for (size_t i = 0; i < parser->tokenKindCount; ++i) {
      parser->token_kind_to_terminal[i] = -1;
      if (!parser->tokenKindStr || !parser->tokenKindStr[i]) {
        continue;
      }
      parser->token_kind_to_terminal[i] =
          parser_terminal_id(parser, parser->tokenKindStr[i]);
    }
  }

  parser->rule_nonterminal_ids =
      malloc(parser->grammar->rules.size * sizeof(ptrdiff_t));
  if (parser->grammar->rules.size > 0 && !parser->rule_nonterminal_ids) {
    return false;
  }
  for (size_t i = 0; i < parser->grammar->rules.size; ++i) {
    Rule* rule = parser->grammar->rules.items[i];
    ptrdiff_t id = parser_nonterminal_id(parser, rule->left);
    if (id < 0) {
      return false;
    }
    parser->rule_nonterminal_ids[i] = id;
  }
  return true;
}

static bool parser_alloc_tables(LR1Parser* parser) {
  if (!parser) {
    return false;
  }
  parser->state_count = parser->collection.size;

  size_t goto_cells = 0;
  size_t action_cells = 0;
  if (!safe_mul(parser->state_count, parser->nonterminal_count, &goto_cells) ||
      !safe_mul(parser->state_count, parser->terminal_count, &action_cells)) {
    return false;
  }

  parser->goto_table = malloc(goto_cells * sizeof(ptrdiff_t));
  parser->action_table = calloc(action_cells, sizeof(ActionEntry));
  parser->action_present = calloc(action_cells, sizeof(unsigned char));
  if ((goto_cells > 0 && !parser->goto_table) ||
      (action_cells > 0 &&
       (!parser->action_table || !parser->action_present))) {
    return false;
  }
  for (size_t i = 0; i < goto_cells; ++i) {
    parser->goto_table[i] = -1;
  }
  return true;
}

static const char* action_type_name(ActionType type) {
  switch (type) {
    case ACTION_ACCEPT:
      return "accept";
    case ACTION_SHIFT:
      return "shift";
    case ACTION_REDUCE:
      return "reduce";
    default:
      return "unknown";
  }
}

static void print_rule(FILE* stream, const Rule* rule) {
  if (!stream || !rule) {
    return;
  }
  fprintf(stream, "%s ->", rule->left);
  if (rule_is_epsilon(rule)) {
    fprintf(stream, " %s", CPARSE_EPSILON);
    return;
  }
  for (size_t i = 0; i < rule->right.size; ++i) {
    fprintf(stream, " %s", rule->right.items[i]);
  }
}

static void print_action(FILE* stream, const LR1Parser* parser,
                         const Action* action) {
  if (!stream || !action) {
    return;
  }
  if (action->type == ACTION_SHIFT) {
    fprintf(stream, "%s -> state %zu", action_type_name(action->type),
            action->operand);
    return;
  }
  if (action->type == ACTION_REDUCE) {
    fprintf(stream, "%s -> rule %zu (", action_type_name(action->type),
            action->operand);
    if (parser && parser->grammar &&
        action->operand < parser->grammar->rules.size) {
      print_rule(stream, parser->grammar->rules.items[action->operand]);
    } else {
      fprintf(stream, "invalid rule");
    }
    fprintf(stream, ")");
    return;
  }
  fprintf(stream, "%s", action_type_name(action->type));
}

static void print_lr_item(FILE* stream, const LR1Item* item) {
  if (!stream || !item || !item->rule) {
    return;
  }
  fprintf(stream, "%s -> ", item->rule->left);
  size_t rhs_len = rule_symbol_count(item->rule);
  if (rhs_len == 0) {
    if (item->dot == 0) {
      fprintf(stream, "• ");
    }
    fprintf(stream, "%s", CPARSE_EPSILON);
    if (item->dot > 0) {
      fprintf(stream, " •");
    }
  } else {
    for (size_t i = 0; i < rhs_len; ++i) {
      if (i == item->dot) {
        fprintf(stream, "• ");
      }
      fprintf(stream, "%s ", item->rule->right.items[i]);
    }
    if (item->dot >= rhs_len) {
      fprintf(stream, "•");
    }
  }
  fprintf(stream, ", lookahead={");
  for (size_t i = 0; i < item->lookahead.size; ++i) {
    if (i > 0) {
      fprintf(stream, ", ");
    }
    fprintf(stream, "%s", item->lookahead.items[i]);
  }
  fprintf(stream, "}");
}

static bool item_matches_conflict_terminal(const LR1Item* item,
                                           const char* terminal) {
  if (!item || !terminal) {
    return false;
  }
  size_t rhs_len = rule_symbol_count(item->rule);
  if (item->dot < rhs_len &&
      strcmp(item->rule->right.items[item->dot], terminal) == 0) {
    return true;
  }
  if (item->dot >= rhs_len && string_vec_contains(&item->lookahead, terminal)) {
    return true;
  }
  return false;
}

static void print_conflict_items(FILE* stream, const LR1State* state,
                                 const char* terminal, bool matching_only) {
  if (!stream || !state) {
    return;
  }
  for (size_t i = 0; i < state->items.size; ++i) {
    LR1Item* item = state->items.items[i];
    if (matching_only && !item_matches_conflict_terminal(item, terminal)) {
      continue;
    }
    fprintf(stream, "    - ");
    print_lr_item(stream, item);
    fprintf(stream, "\n");
  }
}

static void print_lr_conflict(const LR1Parser* parser, size_t state,
                              const char* terminal, const Action* existing,
                              const Action* incoming) {
  if (!parser || state >= parser->collection.size) {
    return;
  }
  LR1State* lr_state = parser->collection.items[state];
  fprintf(stderr, "LR conflict {\n");
  fprintf(stderr, "  state: %zu\n", state);
  fprintf(stderr, "  terminal: %s\n", terminal ? terminal : "(null)");
  fprintf(stderr, "  existing_action: ");
  print_action(stderr, parser, existing);
  fprintf(stderr, "\n");
  fprintf(stderr, "  incoming_action: ");
  print_action(stderr, parser, incoming);
  fprintf(stderr, "\n");
  fprintf(stderr, "  conflict_items:\n");
  bool has_matching = false;
  for (size_t i = 0; i < lr_state->items.size; ++i) {
    LR1Item* item = lr_state->items.items[i];
    if (item_matches_conflict_terminal(item, terminal)) {
      has_matching = true;
      break;
    }
  }
  print_conflict_items(stderr, lr_state, terminal, has_matching);
  fprintf(stderr, "}\n");
}

static bool add_action(LR1Parser* parser, size_t state, const char* terminal,
                       ActionType type, size_t operand) {
  if (!parser || state >= parser->state_count) {
    return false;
  }
  ptrdiff_t terminal_id = parser_terminal_id(parser, terminal);
  if (terminal_id < 0) {
    return false;
  }

  size_t index = action_table_index(parser, state, (size_t)terminal_id);
  Action incoming = {.type = type, .operand = operand};
  if (parser->action_present[index]) {
    ActionEntry* existing = &parser->action_table[index];
    if (existing->action.type != incoming.type ||
        existing->action.operand != incoming.operand) {
      print_lr_conflict(parser, state, terminal, &existing->action, &incoming);
      return false;
    }
    return true;
  }

  parser->action_present[index] = 1;
  parser->action_table[index].terminal = parser->terminal_symbols[terminal_id];
  parser->action_table[index].action = incoming;
  return true;
}

static bool add_goto(LR1Parser* parser, size_t state, const char* symbol,
                     size_t target) {
  if (!parser || state >= parser->state_count) {
    return false;
  }
  ptrdiff_t nonterminal_id = parser_nonterminal_id(parser, symbol);
  if (nonterminal_id < 0) {
    return false;
  }
  size_t index = goto_table_index(parser, state, (size_t)nonterminal_id);
  if (parser->goto_table[index] >= 0 &&
      parser->goto_table[index] != (ptrdiff_t)target) {
    return false;
  }
  parser->goto_table[index] = (ptrdiff_t)target;
  return true;
}

static size_t parser_state_index(const LR1Parser* parser,
                                 const LR1State* state) {
  for (size_t i = 0; i < parser->collection.size; ++i) {
    if (parser->collection.items[i] == state) {
      return i;
    }
  }
  return (size_t)-1;
}

static bool parser_add_state(LR1Parser* parser, LR1State* state) {
  return ptr_vec_push(&parser->collection, state);
}

static LR1State* parser_find_state(const LR1Parser* parser,
                                   const LR1State* candidate,
                                   bool by_core_only) {
  for (size_t i = 0; i < parser->collection.size; ++i) {
    LR1State* existing = parser->collection.items[i];
    if (by_core_only ? lr1_states_same_core(existing, candidate)
                     : lr1_states_equal(existing, candidate)) {
      return existing;
    }
  }
  return NULL;
}

static const SymbolSetEntry* grammar_first_entry(const Grammar* grammar,
                                                 const char* symbol) {
  return symbol_set_find_const(&grammar->first, symbol);
}

static bool compute_first_sequence(const Grammar* grammar, const Rule* rule,
                                   size_t start_index,
                                   const StringVec* fallback,
                                   StringVec* output) {
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
    const char* symbol = rule->right.items[i];
    if (strcmp(symbol, CPARSE_EPSILON) == 0) {
      continue;
    }
    if (grammar_is_terminal(grammar, symbol) ||
        !grammar_is_nonterminal(grammar, symbol)) {
      if (!string_vec_push_unique(output, (char*)symbol)) {
        return false;
      }
      add_fallback = false;
      break;
    }
    const SymbolSetEntry* first_entry = grammar_first_entry(grammar, symbol);
    if (!first_entry) {
      add_fallback = false;
      break;
    }
    bool epsilon_present = false;
    for (size_t j = 0; j < first_entry->values.size; ++j) {
      const char* candidate = first_entry->values.items[j];
      if (strcmp(candidate, CPARSE_EPSILON) == 0) {
        epsilon_present = true;
      } else if (!string_vec_push_unique(output, (char*)candidate)) {
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

static bool closure(const Grammar* grammar, LR1State* state) {
  bool changed = true;
  while (changed) {
    changed = false;
    for (size_t i = 0; i < state->items.size; ++i) {
      LR1Item* item = state->items.items[i];
      size_t rhs_len = rule_symbol_count(item->rule);
      if (item->dot >= rhs_len) {
        continue;
      }
      const char* symbol = item->rule->right.items[item->dot];
      if (!grammar_is_nonterminal(grammar, symbol)) {
        continue;
      }
      StringVec lookahead;
      if (!compute_first_sequence(grammar, item->rule, item->dot + 1,
                                  &item->lookahead, &lookahead)) {
        return false;
      }
      for (size_t r = 0; r < grammar->rules.size; ++r) {
        Rule* candidate_rule = grammar->rules.items[r];
        if (strcmp(candidate_rule->left, symbol) != 0) {
          continue;
        }
        size_t initial_dot = rule_is_epsilon(candidate_rule)
                                 ? rule_symbol_count(candidate_rule)
                                 : 0;
        LR1Item* existing =
            lr1_state_find_item(state, candidate_rule, initial_dot);
        if (!existing) {
          LR1Item* new_item = lr1_item_create(candidate_rule, initial_dot);
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

static LR1State* goto_state(const Grammar* grammar, const LR1State* state,
                            const char* symbol) {
  LR1State* next = lr1_state_create();
  if (!next) {
    return NULL;
  }
  bool has_item = false;
  for (size_t i = 0; i < state->items.size; ++i) {
    LR1Item* item = state->items.items[i];
    size_t rhs_len = rule_symbol_count(item->rule);
    if (item->dot >= rhs_len) {
      continue;
    }
    const char* current = item->rule->right.items[item->dot];
    if (strcmp(current, symbol) != 0) {
      continue;
    }
    LR1Item* advanced = lr1_item_create(item->rule, item->dot + 1);
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

static bool build_lr1_collection(LR1Parser* parser) {
  Rule* start_rule = parser->grammar->rules.items[0];
  LR1Item* start_item = lr1_item_create(start_rule, 0);
  if (!start_item) {
    return false;
  }
  if (!lr1_item_add_lookahead(start_item, kEndMarker, NULL)) {
    lr1_item_destroy(start_item);
    return false;
  }
  LR1State* start_state = lr1_state_create();
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
    LR1State* state = parser->collection.items[i];
    StringVec symbols;
    string_vec_init(&symbols);
    for (size_t j = 0; j < state->items.size; ++j) {
      LR1Item* item = state->items.items[j];
      size_t rhs_len = rule_symbol_count(item->rule);
      if (item->dot >= rhs_len) {
        continue;
      }
      const char* symbol = item->rule->right.items[item->dot];
      if (strcmp(symbol, CPARSE_EPSILON) == 0) {
        continue;
      }
      string_vec_push_unique(&symbols, (char*)symbol);
    }
    for (size_t s = 0; s < symbols.size; ++s) {
      LR1State* next = goto_state(parser->grammar, state, symbols.items[s]);
      if (!next) {
        continue;
      }
      LR1State* existing = parser_find_state(parser, next, false);
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
      LR1Transition* transition =
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

static LR1Item* lr1_item_clone_core(const LR1Item* item) {
  LR1Item* clone = lr1_item_create(item->rule, item->dot);
  if (!clone) {
    return NULL;
  }
  return clone;
}

static LR1State* lr1_state_clone_core(const LR1State* state) {
  LR1State* clone = lr1_state_create();
  if (!clone) {
    return NULL;
  }
  for (size_t i = 0; i < state->items.size; ++i) {
    LR1Item* item = lr1_item_clone_core(state->items.items[i]);
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

static bool merge_states_into(LR1State* target, const LR1State* source) {
  for (size_t i = 0; i < source->items.size; ++i) {
    LR1Item* source_item = source->items.items[i];
    LR1Item* target_item =
        lr1_state_find_item(target, source_item->rule, source_item->dot);
    if (!target_item) {
      LR1Item* clone = lr1_item_clone_core(source_item);
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

static bool build_lalr_collection(LR1Parser* parser) {
  LR1Parser* lr1_parser =
      parser_create(parser->grammar, parser->lexer, parser->tokenKindStr,
                    parser->tokenKindCount);
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
    LR1State* source = lr1_parser->collection.items[i];
    LR1State* existing = parser_find_state(parser, source, true);
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
    LR1State* source = lr1_parser->collection.items[i];
    LR1State* source_mapped = state_map.items[i];
    for (size_t t = 0; t < source->transitions.size; ++t) {
      LR1Transition* transition = source->transitions.items[t];
      size_t target_index = parser_state_index(lr1_parser, transition->state);
      LR1State* mapped_target = state_map.items[target_index];
      bool exists = false;
      for (size_t existing_index = 0;
           existing_index < source_mapped->transitions.size; ++existing_index) {
        LR1Transition* existing_transition =
            source_mapped->transitions.items[existing_index];
        if (strcmp(existing_transition->symbol, transition->symbol) == 0 &&
            existing_transition->state == mapped_target) {
          exists = true;
          break;
        }
      }
      if (!exists) {
        LR1Transition* new_transition =
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

static ptrdiff_t grammar_rule_index(const Grammar* grammar, const Rule* rule) {
  for (size_t i = 0; i < grammar->rules.size; ++i) {
    if (grammar->rules.items[i] == rule) {
      return (ptrdiff_t)i;
    }
  }
  return -1;
}

static bool build_tables(LR1Parser* parser) {
  if (!parser_alloc_tables(parser)) {
    return false;
  }
  for (size_t i = 0; i < parser->collection.size; ++i) {
    LR1State* state = parser->collection.items[i];
    for (size_t t = 0; t < state->transitions.size; ++t) {
      LR1Transition* transition = state->transitions.items[t];
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
      LR1Item* item = state->items.items[item_index];
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
      ptrdiff_t rule_index = grammar_rule_index(parser->grammar, item->rule);
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

LR1Parser* cparseCreateLR1Parser(Grammar* grammar, clexLexer* lexer,
                                 const char* const* tokenKindStr,
                                 size_t tokenKindCount) {
  LR1Parser* parser =
      parser_create(grammar, lexer, tokenKindStr, tokenKindCount);
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

LALR1Parser* cparseCreateLALR1Parser(Grammar* grammar, clexLexer* lexer,
                                     const char* const* tokenKindStr,
                                     size_t tokenKindCount) {
  LR1Parser* parser =
      parser_create(grammar, lexer, tokenKindStr, tokenKindCount);
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

static ActionEntry* parser_get_action(const LR1Parser* parser, size_t state,
                                      size_t terminal_id) {
  if (!parser || state >= parser->state_count ||
      terminal_id >= parser->terminal_count) {
    return NULL;
  }
  size_t index = action_table_index(parser, state, terminal_id);
  if (!parser->action_present[index]) {
    return NULL;
  }
  return &parser->action_table[index];
}

static ptrdiff_t parser_goto_state(const LR1Parser* parser, size_t state,
                                   size_t nonterminal_id) {
  if (!parser || state >= parser->state_count ||
      nonterminal_id >= parser->nonterminal_count) {
    return -1;
  }
  return parser->goto_table[goto_table_index(parser, state, nonterminal_id)];
}

typedef struct {
  size_t* data;
  size_t size;
  size_t capacity;
} SizeTStack;

static void stack_init(SizeTStack* stack) {
  stack->data = NULL;
  stack->size = 0;
  stack->capacity = 0;
}

static void stack_free(SizeTStack* stack) {
  free(stack->data);
  stack->data = NULL;
  stack->size = stack->capacity = 0;
}

static bool stack_reserve(SizeTStack* stack, size_t capacity) {
  if (stack->capacity >= capacity) {
    return true;
  }
  size_t new_capacity = stack->capacity ? stack->capacity : 8;
  while (new_capacity < capacity) {
    new_capacity *= 2;
  }
  size_t* values = realloc(stack->data, new_capacity * sizeof(size_t));
  if (!values) {
    return false;
  }
  stack->data = values;
  stack->capacity = new_capacity;
  return true;
}

static bool stack_push(SizeTStack* stack, size_t value) {
  if (!stack_reserve(stack, stack->size + 1)) {
    return false;
  }
  stack->data[stack->size++] = value;
  return true;
}

static bool stack_pop(SizeTStack* stack, size_t* value) {
  if (stack->size == 0) {
    return false;
  }
  if (value) {
    *value = stack->data[stack->size - 1];
  }
  stack->size--;
  return true;
}

static size_t stack_top(const SizeTStack* stack) {
  assert(stack->size > 0);
  return stack->data[stack->size - 1];
}

static bool ptr_vec_push_ptr(PtrVec* vec, void* value) {
  return ptr_vec_push(vec, value);
}

static void* ptr_vec_pop_ptr(PtrVec* vec) {
  if (vec->size == 0) {
    return NULL;
  }
  void* value = vec->items[vec->size - 1];
  vec->size--;
  return value;
}

static ParseTreeNode* parse_tree_node_create(const char* value) {
  ParseTreeNode* node = calloc(1, sizeof(*node));
  if (!node) {
    return NULL;
  }
  node->value = (char*)value;
  ptr_vec_init(&node->children);
  clexTokenInit(&node->token);
  node->token.kind = -1;
  node->span.start = make_position(0, 1, 1);
  node->span.end = make_position(0, 1, 1);
  return node;
}

static ParseTreeNode* parse_tree_node_create_with_token(const char* value,
                                                        clexToken token) {
  ParseTreeNode* node = parse_tree_node_create(value);
  if (!node) {
    return NULL;
  }
  node->token = token;
  node->span = token.span;
  return node;
}

void cparseFreeParseTree(ParseTreeNode* node) {
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

static cparseStatus parser_set_error(LR1Parser* parser, cparseStatus status,
                                     size_t parser_state,
                                     clexSourcePosition position,
                                     int offending_token_kind,
                                     const char* offending_lexeme,
                                     bool include_expected) {
  if (!parser) {
    return status;
  }
  cparseClearError(&parser->last_error);
  parser->last_error.status = status;
  parser->last_error.position = position;
  parser->last_error.offending_token_kind = offending_token_kind;
  parser->last_error.parser_state = parser_state;
  if (!cparse_error_set_offending_lexeme(&parser->last_error,
                                         offending_lexeme)) {
    parser->last_error.status = CPARSE_STATUS_OUT_OF_MEMORY;
    return CPARSE_STATUS_OUT_OF_MEMORY;
  }
  if (include_expected && !cparse_error_fill_expected_for_state(
                              parser, parser_state, &parser->last_error)) {
    parser->last_error.status = CPARSE_STATUS_OUT_OF_MEMORY;
    return CPARSE_STATUS_OUT_OF_MEMORY;
  }
  return status;
}

static void free_children(PtrVec* children) {
  if (!children) {
    return;
  }
  for (size_t i = 0; i < children->size; ++i) {
    cparseFreeParseTree(children->items[i]);
  }
  ptr_vec_free(children, false, NULL);
}

static cparseStatus accept_or_parse(LR1Parser* parser, const char* input,
                                    bool build_tree, ParseTreeNode** out_tree) {
  if (!parser || !parser->lexer) {
    return CPARSE_STATUS_INVALID_ARGUMENT;
  }
  if (build_tree && !out_tree) {
    return CPARSE_STATUS_INVALID_ARGUMENT;
  }

  cparseClearError(&parser->last_error);
  if (out_tree) {
    *out_tree = NULL;
  }

  clexReset(parser->lexer, input);
  bool lex_next = true;
  clexToken token;
  clexTokenInit(&token);
  token.kind = CLEX_TOKEN_EOF;

  SizeTStack state_stack;
  stack_init(&state_stack);
  if (!stack_push(&state_stack, 0)) {
    stack_free(&state_stack);
    return parser_set_error(parser, CPARSE_STATUS_OUT_OF_MEMORY, 0,
                            make_position(0, 1, 1), CLEX_TOKEN_EOF, NULL,
                            false);
  }

  PtrVec symbol_stack;
  ptr_vec_init(&symbol_stack);

  PtrVec node_stack;
  if (build_tree) {
    ptr_vec_init(&node_stack);
  }

  cparseStatus status = CPARSE_STATUS_OK;
  while (true) {
    if (lex_next) {
      free_token(&token);
      clexTokenInit(&token);
      clexStatus lex_status = clex(parser->lexer, &token);
      if (lex_status == CLEX_STATUS_EOF) {
        token.kind = CLEX_TOKEN_EOF;
      } else if (lex_status == CLEX_STATUS_OK) {
      } else if (lex_status == CLEX_STATUS_LEXICAL_ERROR) {
        const clexError* lex_error = clexGetLastError(parser->lexer);
        clexSourcePosition position =
            lex_error ? lex_error->position : token.span.start;
        const char* lexeme = (lex_error && lex_error->offending_lexeme)
                                 ? lex_error->offending_lexeme
                                 : token.lexeme;
        status = parser_set_error(parser, CPARSE_STATUS_LEXICAL_ERROR,
                                  stack_top(&state_stack), position,
                                  CLEX_TOKEN_ERROR, lexeme, true);
        break;
      } else {
        const clexError* lex_error = clexGetLastError(parser->lexer);
        clexSourcePosition position =
            lex_error ? lex_error->position : token.span.start;
        const char* lexeme = (lex_error && lex_error->offending_lexeme)
                                 ? lex_error->offending_lexeme
                                 : token.lexeme;
        status = parser_set_error(parser, CPARSE_STATUS_INTERNAL_ERROR,
                                  stack_top(&state_stack), position, token.kind,
                                  lexeme, false);
        break;
      }
    }
    lex_next = true;

    const char* terminal = NULL;
    size_t terminal_id = 0;
    if (token.kind == CLEX_TOKEN_EOF) {
      terminal = kEndMarker;
      terminal_id = parser->terminal_count - 1;
    } else if (token.kind >= 0) {
      if ((size_t)token.kind >= parser->tokenKindCount ||
          !parser->token_kind_to_terminal) {
        status = parser_set_error(parser, CPARSE_STATUS_INVALID_TOKEN_KIND,
                                  stack_top(&state_stack), token.span.start,
                                  token.kind, token.lexeme, true);
        break;
      }
      ptrdiff_t mapped_terminal_id = parser->token_kind_to_terminal[token.kind];
      if (mapped_terminal_id < 0 ||
          (size_t)mapped_terminal_id >= parser->terminal_count) {
        status = parser_set_error(parser, CPARSE_STATUS_INVALID_TOKEN_KIND,
                                  stack_top(&state_stack), token.span.start,
                                  token.kind, token.lexeme, true);
        break;
      }
      terminal_id = (size_t)mapped_terminal_id;
      terminal = parser->terminal_symbols[terminal_id];
    } else {
      status = parser_set_error(parser, CPARSE_STATUS_INTERNAL_ERROR,
                                stack_top(&state_stack), token.span.start,
                                token.kind, token.lexeme, false);
      break;
    }

    size_t current_state = stack_top(&state_stack);
    ActionEntry* action = parser_get_action(parser, current_state, terminal_id);
    if (!action) {
      const char* offending =
          token.kind == CLEX_TOKEN_EOF ? "EOF" : token.lexeme;
      status = parser_set_error(parser, CPARSE_STATUS_UNEXPECTED_TOKEN,
                                current_state, token.span.start, token.kind,
                                offending, true);
      break;
    }

    if (action->action.type == ACTION_SHIFT) {
      if (!ptr_vec_push_ptr(&symbol_stack, (void*)terminal)) {
        status =
            parser_set_error(parser, CPARSE_STATUS_OUT_OF_MEMORY, current_state,
                             token.span.start, token.kind, token.lexeme, false);
        break;
      }
      if (!stack_push(&state_stack, action->action.operand)) {
        status =
            parser_set_error(parser, CPARSE_STATUS_OUT_OF_MEMORY, current_state,
                             token.span.start, token.kind, token.lexeme, false);
        break;
      }
      if (build_tree) {
        ParseTreeNode* leaf =
            parse_tree_node_create_with_token(terminal, token);
        if (!leaf) {
          status = parser_set_error(parser, CPARSE_STATUS_OUT_OF_MEMORY,
                                    current_state, token.span.start, token.kind,
                                    token.lexeme, false);
          break;
        }
        if (!ptr_vec_push_ptr(&node_stack, leaf)) {
          cparseFreeParseTree(leaf);
          status = parser_set_error(parser, CPARSE_STATUS_OUT_OF_MEMORY,
                                    current_state, token.span.start, token.kind,
                                    token.lexeme, false);
          break;
        }
        token.lexeme = NULL;
      } else {
        free_token(&token);
      }
    } else if (action->action.type == ACTION_REDUCE) {
      if (action->action.operand >= parser->grammar->rules.size) {
        status = parser_set_error(parser, CPARSE_STATUS_INTERNAL_ERROR,
                                  current_state, token.span.start, token.kind,
                                  token.lexeme, false);
        break;
      }
      Rule* rule = parser->grammar->rules.items[action->action.operand];
      size_t rhs_len = rule_symbol_count(rule);
      PtrVec children;
      if (build_tree) {
        ptr_vec_init(&children);
      }
      bool reduce_failed = false;
      for (size_t i = 0; i < rhs_len; ++i) {
        ptr_vec_pop_ptr(&symbol_stack);
        stack_pop(&state_stack, NULL);
        if (build_tree) {
          ParseTreeNode* child = ptr_vec_pop_ptr(&node_stack);
          if (!ptr_vec_push_ptr(&children, child)) {
            reduce_failed = true;
            break;
          }
        }
      }
      if (reduce_failed) {
        if (build_tree) {
          free_children(&children);
        }
        status =
            parser_set_error(parser, CPARSE_STATUS_OUT_OF_MEMORY, current_state,
                             token.span.start, token.kind, token.lexeme, false);
        break;
      }
      size_t next_state_index = stack_top(&state_stack);
      ptrdiff_t nonterminal_id =
          parser->rule_nonterminal_ids[action->action.operand];
      if (nonterminal_id < 0) {
        if (build_tree) {
          free_children(&children);
        }
        status = parser_set_error(parser, CPARSE_STATUS_INTERNAL_ERROR,
                                  current_state, token.span.start, token.kind,
                                  token.lexeme, false);
        break;
      }
      ptrdiff_t goto_state_value =
          parser_goto_state(parser, next_state_index, (size_t)nonterminal_id);
      if (goto_state_value < 0) {
        if (build_tree) {
          free_children(&children);
        }
        status = parser_set_error(parser, CPARSE_STATUS_INTERNAL_ERROR,
                                  current_state, token.span.start, token.kind,
                                  token.lexeme, false);
        break;
      }
      if (!ptr_vec_push_ptr(&symbol_stack, rule->left)) {
        if (build_tree) {
          free_children(&children);
        }
        status =
            parser_set_error(parser, CPARSE_STATUS_OUT_OF_MEMORY, current_state,
                             token.span.start, token.kind, token.lexeme, false);
        break;
      }
      if (!stack_push(&state_stack, (size_t)goto_state_value)) {
        if (build_tree) {
          free_children(&children);
        }
        status =
            parser_set_error(parser, CPARSE_STATUS_OUT_OF_MEMORY, current_state,
                             token.span.start, token.kind, token.lexeme, false);
        break;
      }
      lex_next = false;
      if (build_tree) {
        ParseTreeNode* parent = parse_tree_node_create(rule->left);
        if (!parent) {
          free_children(&children);
          status = parser_set_error(parser, CPARSE_STATUS_OUT_OF_MEMORY,
                                    current_state, token.span.start, token.kind,
                                    token.lexeme, false);
          break;
        }
        for (size_t i = children.size; i > 0; --i) {
          ParseTreeNode* child = children.items[i - 1];
          if (!ptr_vec_push_ptr(&parent->children, child)) {
            cparseFreeParseTree(parent);
            free_children(&children);
            status = parser_set_error(parser, CPARSE_STATUS_OUT_OF_MEMORY,
                                      current_state, token.span.start,
                                      token.kind, token.lexeme, false);
            reduce_failed = true;
            break;
          }
          children.items[i - 1] = NULL;
        }
        if (reduce_failed) {
          break;
        }
        ptr_vec_free(&children, false, NULL);
        if (parent->children.size > 0) {
          ParseTreeNode* first = parent->children.items[0];
          ParseTreeNode* last =
              parent->children.items[parent->children.size - 1];
          parent->span.start = first->span.start;
          parent->span.end = last->span.end;
        } else {
          parent->span.start = token.span.start;
          parent->span.end = token.span.start;
        }
        if (!ptr_vec_push_ptr(&node_stack, parent)) {
          cparseFreeParseTree(parent);
          status = parser_set_error(parser, CPARSE_STATUS_OUT_OF_MEMORY,
                                    current_state, token.span.start, token.kind,
                                    token.lexeme, false);
          break;
        }
      }
    } else if (action->action.type == ACTION_ACCEPT) {
      status = CPARSE_STATUS_OK;
      break;
    }
  }

  if (status != CPARSE_STATUS_OK) {
    free_token(&token);
    if (build_tree) {
      while (node_stack.size > 0) {
        ParseTreeNode* node = ptr_vec_pop_ptr(&node_stack);
        cparseFreeParseTree(node);
      }
      ptr_vec_free(&node_stack, false, NULL);
    }
    ptr_vec_free(&symbol_stack, false, NULL);
    stack_free(&state_stack);
    return status;
  }

  if (build_tree) {
    ParseTreeNode* root =
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
  return CPARSE_STATUS_OK;
}

cparseStatus cparseAccept(LR1Parser* parser, const char* input) {
  return accept_or_parse(parser, input, false, NULL);
}

cparseStatus cparse(LR1Parser* parser, const char* input,
                    ParseTreeNode** out_tree) {
  return accept_or_parse(parser, input, true, out_tree);
}

typedef struct {
  char* data;
  size_t size;
  size_t capacity;
} StringBuilder;

static bool sb_init(StringBuilder* sb, size_t capacity) {
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

static bool sb_reserve(StringBuilder* sb, size_t additional) {
  size_t required = sb->size + additional + 1;
  if (required <= sb->capacity) {
    return true;
  }
  size_t new_capacity = sb->capacity ? sb->capacity : 128;
  while (new_capacity < required) {
    new_capacity *= 2;
  }
  char* data = realloc(sb->data, new_capacity);
  if (!data) {
    return false;
  }
  sb->data = data;
  sb->capacity = new_capacity;
  return true;
}

static bool sb_append(StringBuilder* sb, const char* text) {
  size_t len = strlen(text);
  if (!sb_reserve(sb, len)) {
    return false;
  }
  memcpy(sb->data + sb->size, text, len);
  sb->size += len;
  sb->data[sb->size] = '\0';
  return true;
}

static bool sb_append_int(StringBuilder* sb, size_t value) {
  char buffer[32];
  snprintf(buffer, sizeof(buffer), "%zu", value);
  return sb_append(sb, buffer);
}

char* getLR1ParserAsString(LR1Parser* parser) {
  if (!parser) {
    return NULL;
  }
  StringBuilder sb;
  if (!sb_init(&sb, 256)) {
    return NULL;
  }
  sb_append(&sb, "States:\n");
  for (size_t i = 0; i < parser->collection.size; ++i) {
    LR1State* state = parser->collection.items[i];
    sb_append(&sb, "State ");
    sb_append_int(&sb, i);
    sb_append(&sb, ":\n");
    for (size_t j = 0; j < state->items.size; ++j) {
      LR1Item* item = state->items.items[j];
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
        LR1Transition* transition = state->transitions.items[t];
        sb_append(&sb, "    ");
        sb_append(&sb, transition->symbol);
        sb_append(&sb, " -> ");
        sb_append_int(&sb, parser_state_index(parser, transition->state));
        sb_append(&sb, "\n");
      }
    }
  }
  sb_append(&sb, "Goto table:\n");
  for (size_t i = 0; i < parser->state_count; ++i) {
    for (size_t j = 0; j < parser->nonterminal_count; ++j) {
      ptrdiff_t target = parser->goto_table[goto_table_index(parser, i, j)];
      if (target < 0) {
        continue;
      }
      sb_append(&sb, "  ");
      sb_append_int(&sb, i);
      sb_append(&sb, " ");
      sb_append(&sb, parser->nonterminal_symbols[j]);
      sb_append(&sb, " -> ");
      sb_append_int(&sb, (size_t)target);
      sb_append(&sb, "\n");
    }
  }
  sb_append(&sb, "Action table:\n");
  for (size_t i = 0; i < parser->state_count; ++i) {
    for (size_t j = 0; j < parser->terminal_count; ++j) {
      size_t index = action_table_index(parser, i, j);
      if (!parser->action_present[index]) {
        continue;
      }
      ActionEntry* entry = &parser->action_table[index];
      sb_append(&sb, "  ");
      sb_append_int(&sb, i);
      sb_append(&sb, " ");
      sb_append(&sb, entry->terminal);
      sb_append(&sb, " -> ");
      sb_append_int(&sb, (size_t)entry->action.type);
      sb_append(&sb, " ");
      sb_append_int(&sb, entry->action.operand);
      sb_append(&sb, "\n");
    }
  }
  return sb.data;
}

char* getParseTreeAsString(ParseTreeNode* root) {
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
    ParseTreeNode* node = ptr_vec_pop_ptr(&stack);
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

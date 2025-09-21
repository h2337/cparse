#include "grammar.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cparse.h"

static Rule *rule_create(const char *left) {
  Rule *rule = calloc(1, sizeof(*rule));
  if (!rule) {
    return NULL;
  }
  rule->left = cparse_strdup(left);
  if (!rule->left) {
    free(rule);
    return NULL;
  }
  string_vec_init(&rule->right);
  return rule;
}

static void rule_destroy(void *ptr) {
  Rule *rule = ptr;
  if (!rule) {
    return;
  }
  free(rule->left);
  string_vec_free(&rule->right, true);
  free(rule);
}

static Grammar *grammar_create(void) {
  Grammar *grammar = calloc(1, sizeof(*grammar));
  if (!grammar) {
    return NULL;
  }
  ptr_vec_init(&grammar->rules);
  string_vec_init(&grammar->terminals);
  string_vec_init(&grammar->nonterminals);
  symbol_set_init(&grammar->first);
  symbol_set_init(&grammar->follow);
  return grammar;
}

void cparseFreeGrammar(Grammar *grammar) {
  if (!grammar) {
    return;
  }
  ptr_vec_free(&grammar->rules, true, rule_destroy);
  string_vec_free(&grammar->terminals, true);
  string_vec_free(&grammar->nonterminals, true);
  free(grammar->start);
  symbol_set_free(&grammar->first);
  symbol_set_free(&grammar->follow);
  free(grammar);
}

static bool grammar_is_terminal(const Grammar *grammar, const char *symbol) {
  if (!symbol || strcmp(symbol, CPARSE_EPSILON) == 0) {
    return false;
  }
  return string_vec_contains(&grammar->terminals, symbol);
}

static bool grammar_is_nonterminal(const Grammar *grammar, const char *symbol) {
  return string_vec_contains(&grammar->nonterminals, symbol);
}

static size_t symbol_set_cardinality(const SymbolSet *set) {
  if (!set) {
    return 0;
  }
  size_t count = 0;
  for (size_t i = 0; i < set->size; ++i) {
    count += set->entries[i].values.size;
  }
  return count;
}

static bool compute_first_sets(Grammar *grammar) {
  size_t previous_total = 0;
  bool first_iteration = true;
  do {
    previous_total = symbol_set_cardinality(&grammar->first);
    for (size_t r = 0; r < grammar->rules.size; ++r) {
      Rule *rule = ptr_vec_get(&grammar->rules, r);
      if (!rule) {
        continue;
      }
      const char *left = rule->left;
      bool derives_epsilon = true;
      if (rule->right.size == 0) {
        if (!symbol_set_add(&grammar->first, left, CPARSE_EPSILON)) {
          return false;
        }
        continue;
      }
      for (size_t i = 0; i < rule->right.size; ++i) {
        const char *symbol = string_vec_get(&rule->right, i);
        if (!symbol) {
          continue;
        }
        if (strcmp(symbol, CPARSE_EPSILON) == 0) {
          if (!symbol_set_add(&grammar->first, left, CPARSE_EPSILON)) {
            return false;
          }
          derives_epsilon = true;
          break;
        }
        if (grammar_is_terminal(grammar, symbol)) {
          if (!symbol_set_add(&grammar->first, left, symbol)) {
            return false;
          }
          derives_epsilon = false;
          break;
        }
        if (!grammar_is_nonterminal(grammar, symbol)) {
          if (!symbol_set_add(&grammar->first, left, symbol)) {
            return false;
          }
          derives_epsilon = false;
          break;
        }
        const SymbolSetEntry *entry =
            symbol_set_find_const(&grammar->first, symbol);
        if (entry) {
          for (size_t j = 0; j < entry->values.size; ++j) {
            const char *candidate = entry->values.items[j];
            if (strcmp(candidate, CPARSE_EPSILON) != 0) {
              if (!symbol_set_add(&grammar->first, left, candidate)) {
                return false;
              }
            }
          }
          if (!string_vec_contains(&entry->values, CPARSE_EPSILON)) {
            derives_epsilon = false;
            break;
          }
        } else {
          derives_epsilon = false;
          break;
        }
        if (i == rule->right.size - 1) {
          derives_epsilon = true;
        }
      }
      if (derives_epsilon) {
        if (!symbol_set_add(&grammar->first, left, CPARSE_EPSILON)) {
          return false;
        }
      }
    }
    size_t current_total = symbol_set_cardinality(&grammar->first);
    if (!first_iteration && current_total == previous_total) {
      break;
    }
    first_iteration = false;
  } while (true);
  return true;
}

static bool first_contains_epsilon(const Grammar *grammar, const char *symbol) {
  const SymbolSetEntry *entry = symbol_set_find_const(&grammar->first, symbol);
  if (!entry) {
    return false;
  }
  return string_vec_contains(&entry->values, CPARSE_EPSILON);
}

static bool compute_follow_sets(Grammar *grammar) {
  for (size_t i = 0; i < grammar->nonterminals.size; ++i) {
    const char *nonterminal = grammar->nonterminals.items[i];
    if (!symbol_set_get(&grammar->follow, nonterminal, true)) {
      return false;
    }
  }
  if (!symbol_set_add(&grammar->follow, grammar->start, "$")) {
    return false;
  }
  while (true) {
    size_t before = symbol_set_cardinality(&grammar->follow);
    for (size_t r = 0; r < grammar->rules.size; ++r) {
      Rule *rule = ptr_vec_get(&grammar->rules, r);
      if (!rule) {
        continue;
      }
      for (size_t i = 0; i < rule->right.size; ++i) {
        const char *symbol = string_vec_get(&rule->right, i);
        if (!grammar_is_nonterminal(grammar, symbol)) {
          continue;
        }
        bool epsilon_needed = true;
        for (size_t j = i + 1; j < rule->right.size; ++j) {
          const char *beta = string_vec_get(&rule->right, j);
          if (strcmp(beta, CPARSE_EPSILON) == 0) {
            continue;
          }
          if (grammar_is_terminal(grammar, beta) ||
              !grammar_is_nonterminal(grammar, beta)) {
            if (!symbol_set_add(&grammar->follow, symbol, beta)) {
              return false;
            }
            epsilon_needed = false;
            break;
          }
          const SymbolSetEntry *first_beta =
              symbol_set_find_const(&grammar->first, beta);
          if (first_beta) {
            for (size_t v = 0; v < first_beta->values.size; ++v) {
              const char *candidate = first_beta->values.items[v];
              if (strcmp(candidate, CPARSE_EPSILON) != 0) {
                if (!symbol_set_add(&grammar->follow, symbol, candidate)) {
                  return false;
                }
              }
            }
            if (!first_contains_epsilon(grammar, beta)) {
              epsilon_needed = false;
              break;
            }
          } else {
            epsilon_needed = false;
            break;
          }
        }
        if (epsilon_needed) {
          const SymbolSetEntry *follow_left =
              symbol_set_find_const(&grammar->follow, rule->left);
          if (follow_left && follow_left->values.size > 0) {
            for (size_t v = 0; v < follow_left->values.size; ++v) {
              if (!symbol_set_add(&grammar->follow, symbol,
                                  follow_left->values.items[v])) {
                return false;
              }
            }
          }
        }
      }
    }
    size_t after = symbol_set_cardinality(&grammar->follow);
    if (after == before) {
      break;
    }
  }
  return true;
}

Grammar *cparseGrammar(const char *grammarString) {
  if (!grammarString) {
    return NULL;
  }
  Grammar *grammar = grammar_create();
  if (!grammar) {
    return NULL;
  }
  StringVec rhs_symbols;
  string_vec_init(&rhs_symbols);
  char *buffer = cparse_strdup(grammarString);
  if (!buffer) {
    cparseFreeGrammar(grammar);
    return NULL;
  }
  char *line_cursor = buffer;
  while (*line_cursor) {
    char *line_start = line_cursor;
    while (*line_cursor && *line_cursor != '\n') line_cursor++;
    if (*line_cursor == '\n') {
      *line_cursor = '\0';
      line_cursor++;
    }
    char *trimmed = trim_whitespace(line_start);
    if (string_is_blank(trimmed) || trimmed[0] == '#') {
      continue;
    }
    char *arrow = strstr(trimmed, "->");
    if (!arrow) {
      fprintf(stderr, "Invalid production: %s\n", trimmed);
      continue;
    }
    *arrow = '\0';
    char *left_raw = trim_whitespace(trimmed);
    char *right_raw = trim_whitespace(arrow + 2);
    if (!left_raw || left_raw[0] == '\0') {
      fprintf(stderr, "Production with empty left-hand side ignored.\n");
      continue;
    }
    if (!grammar->start) {
      grammar->start = cparse_strdup(left_raw);
      if (!grammar->start) {
        free(buffer);
        string_vec_free(&rhs_symbols, false);
        cparseFreeGrammar(grammar);
        return NULL;
      }
    }
    char *right_copy = cparse_strdup(right_raw);
    if (!right_copy) {
      free(buffer);
      string_vec_free(&rhs_symbols, false);
      cparseFreeGrammar(grammar);
      return NULL;
    }
    if (!string_vec_contains(&grammar->nonterminals, left_raw)) {
      if (!string_vec_push_copy(&grammar->nonterminals, left_raw)) {
        free(right_copy);
        free(buffer);
        string_vec_free(&rhs_symbols, false);
        cparseFreeGrammar(grammar);
        return NULL;
      }
    }

    char *alt_cursor = right_copy;
    while (*alt_cursor) {
      char *alt_start = alt_cursor;
      while (*alt_cursor && *alt_cursor != '|') alt_cursor++;
      char saved = *alt_cursor;
      *alt_cursor = '\0';
      char *alt_trim = trim_whitespace(alt_start);
      if (string_is_blank(alt_trim)) {
        if (saved == '\0') {
          break;
        }
        *alt_cursor = saved;
        alt_cursor++;
        continue;
      }
      Rule *rule = rule_create(left_raw);
      if (!rule) {
        free(right_copy);
        free(buffer);
        string_vec_free(&rhs_symbols, false);
        cparseFreeGrammar(grammar);
        return NULL;
      }
      StringVec symbols = split_whitespace(alt_trim);
      if (symbols.size == 0) {
        if (!string_vec_push_copy(&rule->right, CPARSE_EPSILON)) {
          string_vec_free(&symbols, true);
          rule_destroy(rule);
          free(right_copy);
          free(buffer);
          string_vec_free(&rhs_symbols, false);
          cparseFreeGrammar(grammar);
          return NULL;
        }
      } else {
        for (size_t i = 0; i < symbols.size; ++i) {
          char *sym = symbols.items[i];
          if (!string_vec_push(&rule->right, sym)) {
            symbols.items[i] = NULL;
            string_vec_free(&symbols, true);
            rule_destroy(rule);
            free(right_copy);
            free(buffer);
            string_vec_free(&rhs_symbols, false);
            cparseFreeGrammar(grammar);
            return NULL;
          }
          symbols.items[i] = NULL;
          if (strcmp(sym, CPARSE_EPSILON) != 0) {
            if (!string_vec_push_unique(&rhs_symbols, sym)) {
              string_vec_free(&symbols, true);
              rule_destroy(rule);
              free(right_copy);
              free(buffer);
              string_vec_free(&rhs_symbols, false);
              cparseFreeGrammar(grammar);
              return NULL;
            }
          }
        }
      }
      string_vec_free(&symbols, true);
      if (!ptr_vec_push(&grammar->rules, rule)) {
        rule_destroy(rule);
        free(right_copy);
        free(buffer);
        string_vec_free(&rhs_symbols, false);
        cparseFreeGrammar(grammar);
        return NULL;
      }
      if (saved == '\0') {
        break;
      }
      *alt_cursor = saved;
      alt_cursor++;
    }
    free(right_copy);
  }
  free(buffer);

  if (!grammar->start) {
    string_vec_free(&rhs_symbols, false);
    cparseFreeGrammar(grammar);
    return NULL;
  }

  if (!string_vec_push_unique_copy(&grammar->nonterminals,
                                   CPARSE_START_SYMBOL)) {
    string_vec_free(&rhs_symbols, false);
    cparseFreeGrammar(grammar);
    return NULL;
  }
  Rule *augmented = rule_create(CPARSE_START_SYMBOL);
  if (!augmented) {
    string_vec_free(&rhs_symbols, false);
    cparseFreeGrammar(grammar);
    return NULL;
  }
  if (!string_vec_push_copy(&augmented->right, grammar->start)) {
    rule_destroy(augmented);
    string_vec_free(&rhs_symbols, false);
    cparseFreeGrammar(grammar);
    return NULL;
  }

  PtrVec new_rules;
  ptr_vec_init(&new_rules);
  if (!ptr_vec_reserve(&new_rules, grammar->rules.size + 1)) {
    ptr_vec_free(&new_rules, false, NULL);
    rule_destroy(augmented);
    string_vec_free(&rhs_symbols, false);
    cparseFreeGrammar(grammar);
    return NULL;
  }
  if (!ptr_vec_push(&new_rules, augmented)) {
    ptr_vec_free(&new_rules, false, NULL);
    rule_destroy(augmented);
    string_vec_free(&rhs_symbols, false);
    cparseFreeGrammar(grammar);
    return NULL;
  }
  for (size_t i = 0; i < grammar->rules.size; ++i) {
    if (!ptr_vec_push(&new_rules, grammar->rules.items[i])) {
      ptr_vec_free(&new_rules, false, NULL);
      rule_destroy(augmented);
      string_vec_free(&rhs_symbols, false);
      cparseFreeGrammar(grammar);
      return NULL;
    }
  }
  free(grammar->rules.items);
  grammar->rules = new_rules;

  for (size_t i = 0; i < rhs_symbols.size; ++i) {
    const char *symbol = rhs_symbols.items[i];
    if (!string_vec_contains(&grammar->nonterminals, symbol)) {
      if (!string_vec_push_unique_copy(&grammar->terminals, symbol)) {
        cparseFreeGrammar(grammar);
        return NULL;
      }
    }
  }
  string_vec_free(&rhs_symbols, false);

  if (!compute_first_sets(grammar)) {
    cparseFreeGrammar(grammar);
    return NULL;
  }
  if (!compute_follow_sets(grammar)) {
    cparseFreeGrammar(grammar);
    return NULL;
  }
  return grammar;
}

typedef struct {
  char *data;
  size_t size;
  size_t capacity;
} StringBuilder;

static bool sb_init(StringBuilder *sb, size_t initial_capacity) {
  sb->data = malloc(initial_capacity);
  if (!sb->data) {
    sb->size = sb->capacity = 0;
    return false;
  }
  sb->size = 0;
  sb->capacity = initial_capacity;
  sb->data[0] = '\0';
  return true;
}

static bool sb_reserve(StringBuilder *sb, size_t additional) {
  size_t required = sb->size + additional + 1;
  if (required <= sb->capacity) {
    return true;
  }
  size_t new_capacity = sb->capacity ? sb->capacity : 64;
  while (new_capacity < required) {
    new_capacity *= 2;
  }
  char *new_data = realloc(sb->data, new_capacity);
  if (!new_data) {
    return false;
  }
  sb->data = new_data;
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

static bool sb_append_symbol_list(StringBuilder *sb, const StringVec *symbols) {
  for (size_t i = 0; i < symbols->size; ++i) {
    if (!sb_append(sb, i == 0 ? "" : " ")) {
      return false;
    }
    if (!sb_append(sb, symbols->items[i])) {
      return false;
    }
  }
  return true;
}

char *getGrammarAsString(Grammar *grammar) {
  if (!grammar) {
    return NULL;
  }
  StringBuilder sb;
  if (!sb_init(&sb, 256)) {
    return NULL;
  }
  sb_append(&sb, "Start nonterminal: ");
  sb_append(&sb, grammar->start ? grammar->start : "<unset>");
  sb_append(&sb, "\nTerminals:");
  if (grammar->terminals.size > 0) {
    sb_append(&sb, " ");
    for (size_t i = 0; i < grammar->terminals.size; ++i) {
      if (i > 0) {
        sb_append(&sb, " ");
      }
      sb_append(&sb, grammar->terminals.items[i]);
    }
  }
  sb_append(&sb, "\nNon-terminals:");
  if (grammar->nonterminals.size > 0) {
    sb_append(&sb, " ");
    for (size_t i = 0; i < grammar->nonterminals.size; ++i) {
      if (i > 0) {
        sb_append(&sb, " ");
      }
      sb_append(&sb, grammar->nonterminals.items[i]);
    }
  }
  sb_append(&sb, "\nRules:");
  for (size_t i = 0; i < grammar->rules.size; ++i) {
    Rule *rule = grammar->rules.items[i];
    sb_append(&sb, i == 0 ? " " : " && ");
    sb_append(&sb, rule->left);
    sb_append(&sb, " ->");
    if (rule->right.size == 0) {
      sb_append(&sb, " epsilon");
    } else {
      sb_append(&sb, " ");
      sb_append_symbol_list(&sb, &rule->right);
    }
  }
  sb_append(&sb, "\nFirst set:");
  for (size_t i = 0; i < grammar->first.size; ++i) {
    const SymbolSetEntry *entry = &grammar->first.entries[i];
    sb_append(&sb, " ");
    sb_append(&sb, entry->key);
    sb_append(&sb, ": [");
    for (size_t j = 0; j < entry->values.size; ++j) {
      if (j > 0) {
        sb_append(&sb, ", ");
      }
      sb_append(&sb, entry->values.items[j]);
    }
    sb_append(&sb, "]");
  }
  sb_append(&sb, "\nFollow set:");
  for (size_t i = 0; i < grammar->follow.size; ++i) {
    const SymbolSetEntry *entry = &grammar->follow.entries[i];
    sb_append(&sb, " ");
    sb_append(&sb, entry->key);
    sb_append(&sb, ": [");
    for (size_t j = 0; j < entry->values.size; ++j) {
      if (j > 0) {
        sb_append(&sb, ", ");
      }
      sb_append(&sb, entry->values.items[j]);
    }
    sb_append(&sb, "]");
  }
  return sb.data;
}

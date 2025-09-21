#ifndef CPARSE_UTIL_H
#define CPARSE_UTIL_H

#include <stdbool.h>
#include <stddef.h>

/*
 * Generic resizable containers and helpers used across the parser
 * implementation. These utilities intentionally avoid clever macros in favour
 * of explicit, readable code that makes ownership semantics obvious.
 */

typedef struct {
  size_t size;
  size_t capacity;
  char **items;
} StringVec;

void string_vec_init(StringVec *vec);
bool string_vec_reserve(StringVec *vec, size_t capacity);
bool string_vec_push(StringVec *vec, char *value);
bool string_vec_push_copy(StringVec *vec, const char *value);
bool string_vec_contains(const StringVec *vec, const char *value);
bool string_vec_push_unique(StringVec *vec, char *value);
bool string_vec_push_unique_copy(StringVec *vec, const char *value);
bool string_vec_extend(StringVec *dest, const StringVec *src);
bool string_vec_extend_unique(StringVec *dest, const StringVec *src);
bool string_vec_remove(StringVec *vec, const char *value);
char *string_vec_get(const StringVec *vec, size_t index);
char *string_vec_back(const StringVec *vec);
StringVec string_vec_clone(const StringVec *src);
void string_vec_clear(StringVec *vec, bool free_items);
void string_vec_free(StringVec *vec, bool free_items);

typedef struct {
  size_t size;
  size_t capacity;
  void **items;
} PtrVec;

void ptr_vec_init(PtrVec *vec);
bool ptr_vec_reserve(PtrVec *vec, size_t capacity);
bool ptr_vec_push(PtrVec *vec, void *value);
void *ptr_vec_get(const PtrVec *vec, size_t index);
void ptr_vec_remove_swap(PtrVec *vec, size_t index);
void ptr_vec_clear(PtrVec *vec, bool free_items, void (*free_fn)(void *));
void ptr_vec_free(PtrVec *vec, bool free_items, void (*free_fn)(void *));

typedef struct {
  char *key;
  StringVec values;
} SymbolSetEntry;

typedef struct {
  SymbolSetEntry *entries;
  size_t size;
  size_t capacity;
} SymbolSet;

void symbol_set_init(SymbolSet *set);
SymbolSetEntry *symbol_set_get(SymbolSet *set, const char *key, bool create);
const SymbolSetEntry *symbol_set_find_const(const SymbolSet *set,
                                            const char *key);
bool symbol_set_add(SymbolSet *set, const char *key, const char *value);
bool symbol_set_add_vec(SymbolSet *set, const char *key,
                        const StringVec *values);
bool symbol_set_contains(const SymbolSet *set, const char *key,
                         const char *value);
void symbol_set_clear(SymbolSet *set);
void symbol_set_free(SymbolSet *set);

char *cparse_strdup(const char *input);
char *trim_whitespace(char *str);
bool string_is_blank(const char *str);
StringVec split_whitespace(const char *str);

#endif

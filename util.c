#include "util.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool string_vec_grow(StringVec* vec, size_t min_capacity) {
  if (vec->capacity >= min_capacity) {
    return true;
  }
  size_t new_capacity = vec->capacity ? vec->capacity : 4;
  while (new_capacity < min_capacity) {
    if (new_capacity > SIZE_MAX / 2) {
      new_capacity = min_capacity;
      break;
    }
    new_capacity *= 2;
  }
  char** new_items = realloc(vec->items, new_capacity * sizeof(char*));
  if (!new_items) {
    return false;
  }
  vec->items = new_items;
  vec->capacity = new_capacity;
  return true;
}

void string_vec_init(StringVec* vec) {
  vec->size = 0;
  vec->capacity = 0;
  vec->items = NULL;
}

bool string_vec_reserve(StringVec* vec, size_t capacity) {
  return string_vec_grow(vec, capacity);
}

bool string_vec_push(StringVec* vec, char* value) {
  if (!string_vec_grow(vec, vec->size + 1)) {
    return false;
  }
  vec->items[vec->size++] = value;
  return true;
}

bool string_vec_push_copy(StringVec* vec, const char* value) {
  char* copy = cparse_strdup(value);
  if (!copy) {
    return false;
  }
  if (!string_vec_push(vec, copy)) {
    free(copy);
    return false;
  }
  return true;
}

bool string_vec_contains(const StringVec* vec, const char* value) {
  if (!vec || !value) {
    return false;
  }
  for (size_t i = 0; i < vec->size; ++i) {
    if (strcmp(vec->items[i], value) == 0) {
      return true;
    }
  }
  return false;
}

bool string_vec_push_unique(StringVec* vec, char* value) {
  if (string_vec_contains(vec, value)) {
    return true;
  }
  return string_vec_push(vec, value);
}

bool string_vec_push_unique_copy(StringVec* vec, const char* value) {
  if (string_vec_contains(vec, value)) {
    return true;
  }
  return string_vec_push_copy(vec, value);
}

bool string_vec_extend(StringVec* dest, const StringVec* src) {
  if (!src) {
    return true;
  }
  if (!string_vec_grow(dest, dest->size + src->size)) {
    return false;
  }
  for (size_t i = 0; i < src->size; ++i) {
    dest->items[dest->size++] = src->items[i];
  }
  return true;
}

bool string_vec_extend_unique(StringVec* dest, const StringVec* src) {
  if (!src) {
    return true;
  }
  for (size_t i = 0; i < src->size; ++i) {
    if (!string_vec_push_unique(dest, src->items[i])) {
      return false;
    }
  }
  return true;
}

bool string_vec_remove(StringVec* vec, const char* value) {
  if (!vec || !value) {
    return false;
  }
  for (size_t i = 0; i < vec->size; ++i) {
    if (strcmp(vec->items[i], value) == 0) {
      // Preserve order because consumers rely on deterministic iteration.
      memmove(&vec->items[i], &vec->items[i + 1],
              (vec->size - i - 1) * sizeof(char*));
      vec->size--;
      return true;
    }
  }
  return false;
}

char* string_vec_get(const StringVec* vec, size_t index) {
  if (!vec || index >= vec->size) {
    return NULL;
  }
  return vec->items[index];
}

char* string_vec_back(const StringVec* vec) {
  if (!vec || vec->size == 0) {
    return NULL;
  }
  return vec->items[vec->size - 1];
}

StringVec string_vec_clone(const StringVec* src) {
  StringVec result;
  string_vec_init(&result);
  if (!src || src->size == 0) {
    return result;
  }
  if (!string_vec_reserve(&result, src->size)) {
    return result;
  }
  for (size_t i = 0; i < src->size; ++i) {
    result.items[i] = src->items[i];
  }
  result.size = src->size;
  return result;
}

void string_vec_clear(StringVec* vec, bool free_items) {
  if (!vec) {
    return;
  }
  if (free_items) {
    for (size_t i = 0; i < vec->size; ++i) {
      free(vec->items[i]);
    }
  }
  vec->size = 0;
}

void string_vec_free(StringVec* vec, bool free_items) {
  if (!vec) {
    return;
  }
  string_vec_clear(vec, free_items);
  free(vec->items);
  vec->items = NULL;
  vec->capacity = 0;
}

static bool ptr_vec_grow(PtrVec* vec, size_t min_capacity) {
  if (vec->capacity >= min_capacity) {
    return true;
  }
  size_t new_capacity = vec->capacity ? vec->capacity : 4;
  while (new_capacity < min_capacity) {
    if (new_capacity > SIZE_MAX / 2) {
      new_capacity = min_capacity;
      break;
    }
    new_capacity *= 2;
  }
  void** items = realloc(vec->items, new_capacity * sizeof(void*));
  if (!items) {
    return false;
  }
  vec->items = items;
  vec->capacity = new_capacity;
  return true;
}

void ptr_vec_init(PtrVec* vec) {
  vec->size = 0;
  vec->capacity = 0;
  vec->items = NULL;
}

bool ptr_vec_reserve(PtrVec* vec, size_t capacity) {
  return ptr_vec_grow(vec, capacity);
}

bool ptr_vec_push(PtrVec* vec, void* value) {
  if (!ptr_vec_grow(vec, vec->size + 1)) {
    return false;
  }
  vec->items[vec->size++] = value;
  return true;
}

void* ptr_vec_get(const PtrVec* vec, size_t index) {
  if (!vec || index >= vec->size) {
    return NULL;
  }
  return vec->items[index];
}

void ptr_vec_remove_swap(PtrVec* vec, size_t index) {
  if (!vec || index >= vec->size) {
    return;
  }
  vec->items[index] = vec->items[vec->size - 1];
  vec->size--;
}

void ptr_vec_clear(PtrVec* vec, bool free_items, void (*free_fn)(void*)) {
  if (!vec) {
    return;
  }
  if (free_items) {
    for (size_t i = 0; i < vec->size; ++i) {
      if (free_fn) {
        free_fn(vec->items[i]);
      } else {
        free(vec->items[i]);
      }
    }
  }
  vec->size = 0;
}

void ptr_vec_free(PtrVec* vec, bool free_items, void (*free_fn)(void*)) {
  if (!vec) {
    return;
  }
  ptr_vec_clear(vec, free_items, free_fn);
  free(vec->items);
  vec->items = NULL;
  vec->capacity = 0;
}

static bool symbol_set_grow(SymbolSet* set, size_t min_capacity) {
  if (set->capacity >= min_capacity) {
    return true;
  }
  size_t new_capacity = set->capacity ? set->capacity : 4;
  while (new_capacity < min_capacity) {
    if (new_capacity > SIZE_MAX / 2) {
      new_capacity = min_capacity;
      break;
    }
    new_capacity *= 2;
  }
  SymbolSetEntry* entries =
      realloc(set->entries, new_capacity * sizeof(SymbolSetEntry));
  if (!entries) {
    return false;
  }
  set->entries = entries;
  set->capacity = new_capacity;
  return true;
}

void symbol_set_init(SymbolSet* set) {
  set->entries = NULL;
  set->size = 0;
  set->capacity = 0;
}

SymbolSetEntry* symbol_set_get(SymbolSet* set, const char* key, bool create) {
  if (!set || !key) {
    return NULL;
  }
  for (size_t i = 0; i < set->size; ++i) {
    if (strcmp(set->entries[i].key, key) == 0) {
      return &set->entries[i];
    }
  }
  if (!create) {
    return NULL;
  }
  if (!symbol_set_grow(set, set->size + 1)) {
    return NULL;
  }
  SymbolSetEntry* entry = &set->entries[set->size++];
  entry->key = cparse_strdup(key);
  if (!entry->key) {
    set->size--;
    return NULL;
  }
  string_vec_init(&entry->values);
  return entry;
}

const SymbolSetEntry* symbol_set_find_const(const SymbolSet* set,
                                            const char* key) {
  if (!set || !key) {
    return NULL;
  }
  for (size_t i = 0; i < set->size; ++i) {
    if (strcmp(set->entries[i].key, key) == 0) {
      return &set->entries[i];
    }
  }
  return NULL;
}

bool symbol_set_add(SymbolSet* set, const char* key, const char* value) {
  SymbolSetEntry* entry = symbol_set_get(set, key, true);
  if (!entry) {
    return false;
  }
  return string_vec_push_unique_copy(&entry->values, value);
}

bool symbol_set_add_vec(SymbolSet* set, const char* key,
                        const StringVec* values) {
  if (!values) {
    return true;
  }
  SymbolSetEntry* entry = symbol_set_get(set, key, true);
  if (!entry) {
    return false;
  }
  for (size_t i = 0; i < values->size; ++i) {
    if (!string_vec_push_unique(&entry->values, values->items[i])) {
      return false;
    }
  }
  return true;
}

bool symbol_set_contains(const SymbolSet* set, const char* key,
                         const char* value) {
  const SymbolSetEntry* entry = symbol_set_find_const(set, key);
  if (!entry) {
    return false;
  }
  return string_vec_contains(&entry->values, value);
}

void symbol_set_clear(SymbolSet* set) {
  if (!set) {
    return;
  }
  for (size_t i = 0; i < set->size; ++i) {
    free(set->entries[i].key);
    string_vec_free(&set->entries[i].values, false);
  }
  set->size = 0;
}

void symbol_set_free(SymbolSet* set) {
  if (!set) {
    return;
  }
  symbol_set_clear(set);
  free(set->entries);
  set->entries = NULL;
  set->capacity = 0;
}

char* cparse_strdup(const char* input) {
  if (!input) {
    return NULL;
  }
  size_t length = strlen(input);
  char* copy = malloc(length + 1);
  if (!copy) {
    return NULL;
  }
  memcpy(copy, input, length + 1);
  return copy;
}

char* trim_whitespace(char* str) {
  if (!str) {
    return NULL;
  }
  while (isspace((unsigned char)*str)) {
    str++;
  }
  if (*str == '\0') {
    return str;
  }
  char* end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end)) {
    --end;
  }
  end[1] = '\0';
  return str;
}

bool string_is_blank(const char* str) {
  if (!str) {
    return true;
  }
  while (*str) {
    if (!isspace((unsigned char)*str)) {
      return false;
    }
    ++str;
  }
  return true;
}

StringVec split_whitespace(const char* str) {
  StringVec vec;
  string_vec_init(&vec);
  if (!str) {
    return vec;
  }
  const char* cursor = str;
  while (*cursor) {
    while (*cursor && isspace((unsigned char)*cursor)) {
      ++cursor;
    }
    if (!*cursor) {
      break;
    }
    const char* start = cursor;
    while (*cursor && !isspace((unsigned char)*cursor)) {
      ++cursor;
    }
    size_t len = (size_t)(cursor - start);
    char* token = malloc(len + 1);
    if (!token) {
      string_vec_free(&vec, true);
      string_vec_init(&vec);
      return vec;
    }
    memcpy(token, start, len);
    token[len] = '\0';
    if (!string_vec_push(&vec, token)) {
      free(token);
      string_vec_free(&vec, true);
      string_vec_init(&vec);
      return vec;
    }
  }
  return vec;
}

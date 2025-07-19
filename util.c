#include "cparse.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

SetItem **makeSet() {
  SetItem **set = calloc(ARRAY_CAPACITY, sizeof(SetItem));
  return set;
}

char **stringToWords(char *string) {
  char **result = calloc(ARRAY_CAPACITY, sizeof(char *));
  char *rest, *token, *stringPtr = string;
  while ((token = strtok_r(stringPtr, " ", &rest))) {
    addCharPtrToArray(result, token);
    stringPtr = rest;
  }
  return result;
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
  for (int i = 0; i < ARRAY_CAPACITY; i++) {
    if (!array[i]) {
      array[i] = value;
      break;
    }
  }
}

void removeCharPtrFromArray(char **array, char *value) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (array[i] && strcmp(array[i], value) == 0) {
      array[i] = NULL;
      for (int j = i + 1; j < ARRAY_CAPACITY; j++) {
        if (!array[j] && array[j - 1]) {
          array[i] = array[j - 1];
          array[j - 1] = NULL;
          i--;
        }
      }
    }
}

void addToSet(SetItem **set, char *key, char *value) {
  if (inSet(set, key, value)) return;
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (set[i] && strcmp(set[i]->key, key) == 0)
      for (int j = 0; j < ARRAY_CAPACITY; j++)
        if (!set[i]->values[j]) {
          set[i]->values[j] = value;
          return;
        }
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (!set[i]) {
      set[i] = calloc(1, sizeof(SetItem));
      set[i]->key = key;
      set[i]->values = calloc(ARRAY_CAPACITY, sizeof(char *));
      set[i]->values[0] = value;
      return;
    }
}

void addToSetItem(SetItem *setItem, char *value) {
  if (inSetItem(setItem, value)) return;
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (!setItem->values[i]) {
      setItem->values[i] = value;
      return;
    }
}

void addAllToSet(SetItem **set, char *key, char **values) {
  if (!values) return;
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (values[i])
      addToSet(set, key, values[i]);
}

void addAllToSetItem(SetItem *setItem, char **values) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (values[i])
      addToSetItem(setItem, values[i]);
}

bool inArray(char **array, char *value) {
  for (int i = 0; i < ARRAY_CAPACITY; i++) {
    if (!array[i])
      return false;
    if (array[i] == value || strcmp(array[i], value) == 0)
      return true;
  }
  return false;
}

bool isArrayEqual(char **a, char **b) {
  if (a == b) return true;
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (a[i])
      if (!b[i] || (a[i] != b[i] && strcmp(a[i], b[i]) != 0))
        return false;
  return true;
}

bool arrayContainsAll(char **a, char **b) {
  if (a == b) return true;
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (!b[i])
      break;
    else if (!inArray(a, b[i]))
      return false;
  return true;
}

bool inSet(SetItem **set, char *key, char *value) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (set[i] && strcmp(set[i]->key, key) == 0)
      for (int j = 0; j < ARRAY_CAPACITY; j++)
        if (set[i]->values[j] && strcmp(set[i]->values[j], value) == 0)
          return true;
  return false;
}

bool isKeyInSet(SetItem **set, char *key) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (set[i] && strcmp(set[i]->key, key) == 0)
      return true;
  return false;
}

bool inSetItem(SetItem *setItem, char *value) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (setItem->values[i] && strcmp(setItem->values[i], value) == 0)
      return true;
  return false;
}

bool allInSetItem(SetItem *setItem, char **values) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (values[i] && !inSetItem(setItem, values[i]))
      return false;
  return true;
}

void removeFromSetItem(SetItem *setItem, char *value) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (setItem->values[i] && strcmp(setItem->values[i], value) == 0)
      setItem->values[i] = NULL;
}

char **findValuesInSet(SetItem **set, char *key) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (set[i] && strcmp(set[i]->key, key) == 0)
      return set[i]->values;
  return NULL;
}

SetItem *findInSet(SetItem **set, char *key) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (set[i] && strcmp(set[i]->key, key) == 0)
      return set[i];
  return NULL;
}

int getValuesLength(char **values) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (!values[i])
      return i;
}

void createSetItem(SetItem **set, char *key) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (!set[i]) {
      set[i] = calloc(1, sizeof(SetItem));
      set[i]->key = key;
      set[i]->values = calloc(ARRAY_CAPACITY, sizeof(char *));
      return;
    }
}

SetItem *copySetItem(SetItem *setItem) {
  SetItem *result = calloc(1, sizeof(SetItem));
  result->values = calloc(ARRAY_CAPACITY, sizeof(char *));
  result->key = setItem->key;
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (setItem->values[i])
      result->values[i] = setItem->values[i];
  return result;
}

char **copyCharArray(char **values) {
  char **result = malloc(ARRAY_CAPACITY * sizeof(char *));
  memcpy(result, values, ARRAY_CAPACITY);
  return result;
}

void addCharPtrToArrayUnique(char **array, char *value) {
  if (!inArray(array, value))
    addCharPtrToArray(array, value);
}

void addAllCharPtrToArrayUnique(char **destination, char **source) {
  for (int i = 0; i < ARRAY_CAPACITY; i++)
    if (source[i])
      addCharPtrToArrayUnique(destination, source[i]);
}


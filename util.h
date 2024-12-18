#ifndef CPARSE_UTIL_H
#define CPARSE_UTIL_H

#include "cparse.h"

SetItem **makeSet();
char **stringToWords(char *string);
char *trim(char *str);
void addCharPtrToArray(char **array, char *value);
void removeCharPtrFromArray(char **array, char *value);
void addToSet(SetItem **set, char *key, char *value);
void addToSetItem(SetItem *setItem, char *value);
void addAllToSet(SetItem **set, char *key, char **values);
void addAllToSetItem(SetItem *setItem, char **values);
bool inArray(char **array, char *value);
bool isArrayEqual(char **a, char **b);
bool arrayContainsAll(char **a, char **b);
bool inSet(SetItem **set, char *key, char *value);
bool isKeyInSet(SetItem **set, char *key);
bool inSetItem(SetItem *setItem, char *value);
bool allInSetItem(SetItem *setItem, char **values);
void removeFromSetItem(SetItem *setItem, char *value);
char **findValuesInSet(SetItem **set, char *key);
SetItem *findInSet(SetItem **set, char *key);
int getValuesLength(char **values);
void createSetItem(SetItem **set, char *key);
SetItem *copySetItem(SetItem *setItem);
char **copyCharArray(char **values);
void addCharPtrToArrayUnique(char **array, char *value);
void addAllCharPtrToArrayUnique(char **destination, char **source);

#endif


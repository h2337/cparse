<img align="right" src="https://github.com/jafarlihi/file-hosting/blob/b51468695319c3768e08ea2f11fcda6bca61551d/cparse2.png?raw=true">

## TOC

* [Overview](#overview)
* [Example](#example)

## Overview

> :warning: cparse is still under development and code is unpolished.

cparse is an LR(1) parser generator for C.

cparse uses [`clex`](https://github.com/jafarlihi/clex) lexer generator for syntactic analysis purposes.

Note that LR(1) parsers are memory-intensive (and there are memory leaks...), so something like full C grammar can require up to 4GBs of free RAM.

## Example

```c
#include "cparse.h"
#include "clex/clex.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

// Create an enum for token types
typedef enum TokenKind {
  INT,
  RETURN,
  SEMICOL,
  IDENTIFIER,
} TokenKind;

// Provide a string representation for each token type to be used in the grammar
const char * const tokenKindStr[] = {
  [INT] = "INT",
  [RETURN] = "RETURN",
  [SEMICOL] = "SEMICOL",
  [IDENTIFIER] = "IDENTIFIER",
};

int main(int argc, char *argv[]) {
  // Register your token types with `clex`
  clexRegisterKind("int", INT);
  clexRegisterKind("return", RETURN);
  clexRegisterKind(";", SEMICOL);
  clexRegisterKind("[a-zA-Z_]([a-zA-Z_]|[0-9])*", IDENTIFIER);

  // Write your grammar
  char grammarString[] =
    "S -> A IDENTIFIER SEMICOL\n"
    "A -> RETURN";

  // Parse your grammar
  Grammar *grammar = cparseGrammar(grammarString);
  // Construct an LR(1) parser
  LR1Parser *parser = cparseCreateLR1Parser(grammar, tokenKindStr);

  // Test if given input is valid within the grammar
  assert(cparseAccept(parser, "return id1;") == true);

  // Parse a given input and get a parse tree
  ParseTreeNode *node = cparse(parser, "return id1;");

  // Use your parse tree
  assert(strcmp(node->value, "S") == 0);
  assert(strcmp(node->children[0]->value, "SEMICOL") == 0);
  assert(node->children[0]->token.kind == SEMICOL);
  assert(strcmp(node->children[0]->token.lexeme, ";") == 0);
  assert(strcmp(node->children[1]->value, "IDENTIFIER") == 0);
  assert(node->children[1]->token.kind == IDENTIFIER);
  assert(strcmp(node->children[1]->token.lexeme, "id1") == 0);
  assert(strcmp(node->children[2]->value, "A") == 0);
  assert(strcmp(node->children[2]->children[0]->value, "RETURN") == 0);
  assert(node->children[2]->children[0]->token.kind == RETURN);
  assert(strcmp(node->children[2]->children[0]->token.lexeme, "return") == 0);
}
```

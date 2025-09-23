<img align="right" src="https://raw.githubusercontent.com/h2337/cparse/refs/heads/master/logo.svg">

# cparse

`cparse` is an LR(1) and LALR(1) parser generator for C. It consumes a grammar written in an intuitive textual format and, together with the [`clex`](https://github.com/h2337/clex) lexer generator, lets you build parsers that can both validate and produce parse trees for input programs.

## Highlights

- Modernised LR(1) and LALR(1) construction written in portable C11.
- Predictable performance via dynamic data structures instead of fixed-size arrays.
- First/Follow set computation with useful diagnostics for malformed grammars.
- Straightforward runtime API (`cparseAccept`, `cparse`) that produces parse trees.
- Ships with a tiny test suite (`make test`) and a static library build (`libcparse.a`).

## Getting Started

```bash
git clone https://github.com/h2337/cparse.git
cd cparse
git submodule update --init --recursive
make test   # builds libcparse.a, the test binary, and runs the tests
```

This project depends only on a C11 compiler. The bundled `clex` submodule is used for lexical analysis in the examples and tests.

## Quick Example

```c
#include "cparse.h"
#include "clex/clex.h"

// Token kinds supplied to clex
enum {
  TOK_RETURN,
  TOK_IDENTIFIER,
  TOK_SEMICOLON,
};

static const char *token_names[] = {
  [TOK_RETURN] = "RETURN",
  [TOK_IDENTIFIER] = "IDENTIFIER",
  [TOK_SEMICOLON] = "SEMICOL",
};

int main(void) {
  clexLexer *lexer = clexInit();
  clexRegisterKind(lexer, "return", TOK_RETURN);
  clexRegisterKind(lexer, "[a-zA-Z_]([a-zA-Z_]|[0-9])*", TOK_IDENTIFIER);
  clexRegisterKind(lexer, ";", TOK_SEMICOLON);

  const char *grammar_src =
      "S -> A IDENTIFIER SEMICOL\n"
      "A -> RETURN";

  Grammar *grammar = cparseGrammar(grammar_src);
  LALR1Parser *parser = cparseCreateLALR1Parser(grammar, lexer, token_names);

  if (cparseAccept(parser, "return answer;")) {
    ParseTreeNode *root = cparse(parser, "return answer;");
    /* ... consume parse tree ... */
    cparseFreeParseTree(root);
  }

  cparseFreeParser(parser);
  cparseFreeGrammar(grammar);
  clexLexerDestroy(lexer);
  return 0;
}
```

## Runtime API

| Function | Description |
|----------|-------------|
| `Grammar *cparseGrammar(const char *grammar_source)` | Parse a grammar description into an internal representation. |
| `LR1Parser *cparseCreateLR1Parser(Grammar *, clexLexer *, const char *const *token_names)` | Build an LR(1) parser (the lexer remains owned by the caller). |
| `LALR1Parser *cparseCreateLALR1Parser(Grammar *, clexLexer *, const char *const *token_names)` | Build an LALR(1) parser by merging LR(1) states (caller retains lexer ownership). |
| `bool cparseAccept(LR1Parser *, const char *input)` | Check whether the input belongs to the grammar. |
| `ParseTreeNode *cparse(LR1Parser *, const char *input)` | Parse input and return the parse tree (or `NULL` on failure). |
| `void cparseFreeParseTree(ParseTreeNode *)` | Recursively release a parse tree allocated by `cparse`. |
| `void cparseFreeParser(LR1Parser *)` | Release parser state (works for LALR parsers as well). |
| `void cparseFreeGrammar(Grammar *)` | Release grammar data structures. |

A parse tree node stores the grammar symbol in `value`, the matched token (for terminals) in `token`, and its children in `children`.

## Building

- `make` or `make tests` builds `libcparse.a`, the supporting objects, and the `tests` binary.
- `make test` runs the regression tests.
- `make examples` builds the sample programs under `examples/`.
- `make clean` removes build artefacts.

You can link `libcparse.a` into your own project together with `clex/clex.o` and `clex/fa.o`, or embed the sources directly.

## Examples

The `examples/` directory contains small, self-contained programs that exercise the library. After running `make examples` you can try the expression parser:

```bash
./examples/expr_parser "8 + 5 * 2"
```

The example registers a handful of tokens, builds an LALR(1) grammar for arithmetic expressions, validates the input, and prints the resulting parse tree.

## Grammar Format

Each line describes a production:

```
NonTerminal -> alternative1 | alternative2 | ...
```

- Tokens are whitespace separated.
- Use `epsilon` to denote an empty production.
- Lines beginning with `#` are treated as comments.

For example:

```
S -> A IDENTIFIER SEMICOL
A -> RETURN | epsilon
```

## Development Notes

- The implementation avoids fixed limits and lazy `strtok()` parsing, making it suitable for larger grammars.
- First and Follow sets are computed iteratively; unexpected productions emit diagnostics on `stderr`.
- The repository includes a tiny test harness in `tests.c`. Extend it with grammar-specific checks as needed.
- Parsers borrow the `clexLexer` you pass; create it up front, register token kinds, and destroy it once you are done with parsing.

## License

Distributed under the terms of the MIT License. See [LICENSE](./LICENSE).

<img align="right" src="https://raw.githubusercontent.com/h2337/cparse/refs/heads/master/logo.svg">

# cparse

`cparse` is an LR(1) and LALR(1) parser generator for C. It consumes a grammar written in an intuitive textual format and, together with the [`clex`](https://github.com/h2337/clex) lexer generator, lets you build parsers that can both validate and produce parse trees for input programs.

## Highlights

- Modernised LR(1) and LALR(1) construction written in portable C11.
- Predictable performance via dynamic data structures instead of fixed-size arrays.
- Index-based action/goto tables keyed by terminal/nonterminal IDs for O(1)
  parse-time table lookups.
- First/Follow set computation with useful diagnostics for malformed grammars.
- Structured LR conflict diagnostics with state details, relevant items, and
  competing actions.
- Typed runtime status codes plus structured parser errors (position, expected
  terminals, offending lexeme).
- Parse trees carry source spans (byte offset + line/column) through terminal
  and nonterminal nodes.
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
  if (clexRegisterKind(lexer, "return", TOK_RETURN) != CLEX_STATUS_OK ||
      clexRegisterKind(lexer, "[a-zA-Z_]([a-zA-Z_]|[0-9])*", TOK_IDENTIFIER) !=
          CLEX_STATUS_OK ||
      clexRegisterKind(lexer, ";", TOK_SEMICOLON) != CLEX_STATUS_OK) {
    return 1;
  }

  const char *grammar_src =
      "S -> A IDENTIFIER SEMICOL\n"
      "A -> RETURN";

  Grammar *grammar = cparseGrammar(grammar_src);
  LALR1Parser *parser =
      cparseCreateLALR1Parser(grammar, lexer, token_names,
                              sizeof(token_names) / sizeof(token_names[0]));

  if (cparseAccept(parser, "return answer;") == CPARSE_STATUS_OK) {
    ParseTreeNode *root = NULL;
    if (cparse(parser, "return answer;", &root) == CPARSE_STATUS_OK) {
      /* ... consume parse tree ... */
    }
    cparseFreeParseTree(root);
  } else {
    const cparseError *err = cparseGetLastError(parser);
    /* inspect err->position, err->expected_tokens, err->offending_lexeme */
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
| `LR1Parser *cparseCreateLR1Parser(Grammar *, clexLexer *, const char *const *token_names, size_t token_name_count)` | Build an LR(1) parser (the lexer remains owned by the caller). |
| `LALR1Parser *cparseCreateLALR1Parser(Grammar *, clexLexer *, const char *const *token_names, size_t token_name_count)` | Build an LALR(1) parser by merging LR(1) states (caller retains lexer ownership). |
| `cparseStatus cparseAccept(LR1Parser *, const char *input)` | Validate input. Returns `CPARSE_STATUS_OK` on success. |
| `cparseStatus cparse(LR1Parser *, const char *input, ParseTreeNode **out_tree)` | Parse input and write the tree to `out_tree` on success. |
| `const cparseError *cparseGetLastError(const LR1Parser *)` | Retrieve structured parser error details after a non-OK status. |
| `void cparseFreeParseTree(ParseTreeNode *)` | Recursively release a parse tree allocated by `cparse`. |
| `void cparseFreeParser(LR1Parser *)` | Release parser state (works for LALR parsers as well). |
| `void cparseFreeGrammar(Grammar *)` | Release grammar data structures. |

A parse tree node stores:
- the grammar symbol in `value`
- the matched token (for terminals) in `token` (including source span)
- an aggregate source span for the node in `span`
- child nodes in `children`

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
- LR conflicts print structured diagnostics to `stderr` (state, terminal,
  existing/incoming action, and relevant LR items) to shorten grammar-debug
  loops.
- The repository includes a tiny test harness in `tests.c`. Extend it with grammar-specific checks as needed.
- Parsers borrow the `clexLexer` you pass; create it up front, register token kinds, and destroy it once you are done with parsing.

## License

Distributed under the terms of the MIT License. See [LICENSE](./LICENSE).

#ifdef TEST_CPARSE

#include "grammar.h"
#include "lr1.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

char *grammar1StringResult = "Start nonterminal: S\n"
"Terminals: a b\n"
"Non-terminals: cparseStart S A B\n"
"Rules: cparseStart -> S && S -> A A && A -> a A && A -> b && B -> #\n"
"First set: A: [a, b] S: [a, b] cparseStart: [a, b] B: [#]\n"
"Follow set: cparseStart: [$] S: [$] A: [a, b, $] B: []";

char *grammar2StringResult = "Start nonterminal: Program\n"
"Terminals: var begin end ; identifier ; read ( ) write ( )\n"
"Non-terminals: cparseStart Program Variables Variables Variable Operators Operators Operator Operator\n"
"Rules: cparseStart -> Program && Program -> var Variables begin Operators end && Variables -> Variable ; Variables && Variables -> # && Variable -> identifier && Operators -> Operator ; Operators && Operators -> # && Operator -> read ( Variable ) && Operator -> write ( Variable )\n"
"First set: Program: [var] cparseStart: [var] Variable: [identifier] Variables: [identifier, #] Operator: [read, write] Operators: [read, write, #]\n"
"Follow set: cparseStart: [$] Program: [$] Variables: [begin] Variable: [;, )] Operators: [end] Operator: [;]";

char *grammar3StringResult = "Start nonterminal: P\n"
"Terminals: + id ( ) id\n"
"Non-terminals: cparseStart P E E T T\n"
"Rules: cparseStart -> P && P -> E && E -> E + T && E -> T && T -> id ( E ) && T -> id\n"
"First set: T: [id] E: [id] P: [id] cparseStart: [id]\n"
"Follow set: cparseStart: [$] P: [$] E: [$, +, )] T: [$, +, )]";

int main(int argc, char *argv[]) {
  char grammarString[] = "S -> A A\nA -> a A | b\nB -> #";
  Grammar *grammar1 = parseGrammar(grammarString);
  printf("%s\n", getGrammarAsString(grammar1));
  assert(strcmp(getGrammarAsString(grammar1), grammar1StringResult) == 0);

  printf("\n");

  char grammarString2[] = "Program -> var Variables begin Operators end\n"
                          "Variables -> Variable ; Variables\n"
                          "Variables -> #\n"
                          "Variable -> identifier\n"
                          "Operators -> Operator ; Operators\n"
                          "Operators -> #\n"
                          "Operator -> read ( Variable )\n"
                          "Operator -> write ( Variable )\n";
  Grammar *grammar2 = parseGrammar(grammarString2);
  printf("%s\n", getGrammarAsString(grammar2));
  assert(strcmp(getGrammarAsString(grammar2), grammar2StringResult) == 0);

  printf("\n");

  char grammarString3[] = "P -> E\n"
                          "E -> E + T\n"
                          "E -> T\n"
                          "T -> id ( E )\n"
                          "T -> id\n";
  Grammar *grammar3 = parseGrammar(grammarString3);
  printf("%s\n", getGrammarAsString(grammar3));
  assert(strcmp(getGrammarAsString(grammar3), grammar3StringResult) == 0);

  printf("\n");

  LR1Parser *parser1 = createLR1Parser(grammar1);
  printf("%s\n", getLR1ParserAsString(parser1));

  printf("\n");

  LR1Parser *parser2 = createLR1Parser(grammar2);
  //printf("%s\n", getLR1ParserAsString(parser2));

  printf("\n");

  LR1Parser *parser3 = createLR1Parser(grammar3);
  //printf("%s\n", getLR1ParserAsString(parser3));
}

#endif


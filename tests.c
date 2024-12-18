#ifdef TEST_CPARSE1

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

  LR1Parser *parser1 = createLR1Parser(grammar1, NULL);
  printf("%s\n", getLR1ParserAsString(parser1));

  printf("\n");

  LR1Parser *parser2 = createLR1Parser(grammar2, NULL);
  printf("%s\n", getLR1ParserAsString(parser2));

  printf("\n");

  LR1Parser *parser3 = createLR1Parser(grammar3, NULL);
  printf("%s\n", getLR1ParserAsString(parser3));
}

#endif

#ifdef TEST_CPARSE2

#include "grammar.h"
#include "lr1.h"
#include "clex/clex.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

typedef enum TokenKind {
  INT,
  OPARAN,
  CPARAN,
  OSQUAREBRACE,
  CSQUAREBRACE,
  OCURLYBRACE,
  CCURLYBRACE,
  COMMA,
  CHAR,
  STAR,
  RETURN,
  SEMICOL,
  CONSTANT,
  IDENTIFIER,
} TokenKind;

const char * const tokenKindStr[] = {
  [INT] = "INT",
  [OPARAN] = "OPARAN",
  [CPARAN] = "CPARAN",
  [OSQUAREBRACE] = "OSQUAREBRACE",
  [CSQUAREBRACE] = "CSQUAREBRACE",
  [OCURLYBRACE] = "OCURLYBRACE",
  [CCURLYBRACE] = "CCURLYBRACE",
  [COMMA] = "COMMA",
  [CHAR] = "CHAR",
  [STAR] = "STAR",
  [RETURN] = "RETURN",
  [SEMICOL] = "SEMICOL",
  [CONSTANT] = "CONSTANT",
  [IDENTIFIER] = "IDENTIFIER",
};

int main(int argc, char *argv[]) {
  clexRegisterKind("int", INT);
  clexRegisterKind("\\(", OPARAN);
  clexRegisterKind("\\)", CPARAN);
  clexRegisterKind("\\[|<:", OSQUAREBRACE);
  clexRegisterKind("\\]|:>", CSQUAREBRACE);
  clexRegisterKind("{|<%", OCURLYBRACE);
  clexRegisterKind("}|%>", CCURLYBRACE);
  clexRegisterKind(",", COMMA);
  clexRegisterKind("char", CHAR);
  clexRegisterKind("\\*", STAR);
  clexRegisterKind("return", RETURN);
  clexRegisterKind("[1-9][0-9]*([uU])?([lL])?([lL])?", CONSTANT);
  clexRegisterKind(";", SEMICOL);
  clexRegisterKind("[a-zA-Z_]([a-zA-Z_]|[0-9])*", IDENTIFIER);

  char grammarString[] = "S -> A IDENTIFIER SEMICOL\nA -> RETURN\n";
  Grammar *grammar = parseGrammar(grammarString);
  printf("%s\n", getGrammarAsString(grammar));
  LR1Parser *parser = createLR1Parser(grammar, tokenKindStr);
  printf("%s\n", getLR1ParserAsString(parser));

  printf("%d\n", accept(parser, "return id1;"));

  ParseTreeNode *node = parse(parser, "return id1;");
  printf("%s\n", getParseTreeAsString(node));
}

#endif

#ifdef TEST_CPARSE3

#include "grammar.h"
#include "lr1.h"
#include "clex/clex.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

#undef EOF

typedef enum TokenKind {
  EOF,
  AUTO,
  BOOL,
  BREAK,
  CASE,
  CHAR,
  COMPLEX,
  CONST,
  CONTINUE,
  DEFAULT,
  DO,
  DOUBLE,
  ELSE,
  ENUM,
  EXTERN,
  FLOAT,
  FOR,
  GOTO,
  IF,
  IMAGINARY,
  INLINE,
  INT,
  LONG,
  REGISTER,
  RESTRICT,
  RETURN,
  SHORT,
  SIGNED,
  SIZEOF,
  STATIC,
  STRUCT,
  SWITCH,
  TYPEDEF,
  UNION,
  UNSIGNED,
  VOID,
  VOLATILE,
  WHILE,
  ELLIPSIS,
  RIGHT_ASSIGN,
  LEFT_ASSIGN,
  ADD_ASSIGN,
  SUB_ASSIGN,
  MUL_ASSIGN,
  DIV_ASSIGN,
  MOD_ASSIGN,
  AND_ASSIGN,
  XOR_ASSIGN,
  OR_ASSIGN,
  RIGHT_OP,
  LEFT_OP,
  INC_OP,
  DEC_OP,
  PTR_OP,
  AND_OP,
  OR_OP,
  LE_OP,
  GE_OP,
  EQ_OP,
  NE_OP,
  SEMICOL,
  OCURLYBRACE,
  CCURLYBRACE,
  COMMA,
  COLON,
  EQUAL,
  OPARAN,
  CPARAN,
  OSQUAREBRACE,
  CSQUAREBRACE,
  DOT,
  AMPER,
  EXCLAMATION,
  TILDE,
  MINUS,
  PLUS,
  STAR,
  SLASH,
  PERCENT,
  RANGLE,
  LANGLE,
  CARET,
  PIPE,
  QUESTION,
  STRINGLITERAL,
  CONSTANT,
  IDENTIFIER,
} TokenKind;

const char * const tokenKindStr[] = {
  [EOF] = "EOF",
  [AUTO] = "AUTO",
  [BOOL] = "BOOL",
  [BREAK] = "BREAK",
  [CASE] = "CASE",
  [CHAR] = "CHAR",
  [COMPLEX] = "COMPLEX",
  [CONST] = "CONST",
  [CONTINUE] = "CONTINUE",
  [DEFAULT] = "DEFAULT",
  [DO] = "DO",
  [DOUBLE] = "DOUBLE",
  [ELSE] = "ELSE",
  [ENUM] = "ENUM",
  [EXTERN] = "EXTERN",
  [FLOAT] = "FLOAT",
  [FOR] = "FOR",
  [GOTO] = "GOTO",
  [IF] = "IF",
  [IMAGINARY] = "IMAGINARY",
  [INLINE] = "INLINE",
  [INT] = "INT",
  [LONG] = "LONG",
  [REGISTER] = "REGISTER",
  [RESTRICT] = "RESTRICT",
  [RETURN] = "RETURN",
  [SHORT] = "SHORT",
  [SIGNED] = "SIGNED",
  [SIZEOF] = "SIZEOF",
  [STATIC] = "STATIC",
  [STRUCT] = "STRUCT",
  [SWITCH] = "SWITCH",
  [TYPEDEF] = "TYPEDEF",
  [UNION] = "UNION",
  [UNSIGNED] = "UNSIGNED",
  [VOID] = "VOID",
  [VOLATILE] = "VOLATILE",
  [WHILE] = "WHILE",
  [ELLIPSIS] = "ELLIPSIS",
  [RIGHT_ASSIGN] = "RIGHT_ASSIGN",
  [LEFT_ASSIGN] = "LEFT_ASSIGN",
  [ADD_ASSIGN] = "ADD_ASSIGN",
  [SUB_ASSIGN] = "SUB_ASSIGN",
  [MUL_ASSIGN] = "MUL_ASSIGN",
  [DIV_ASSIGN] = "DIV_ASSIGN",
  [MOD_ASSIGN] = "MOD_ASSIGN",
  [AND_ASSIGN] = "AND_ASSIGN",
  [XOR_ASSIGN] = "XOR_ASSIGN",
  [OR_ASSIGN] = "OR_ASSIGN",
  [RIGHT_OP] = "RIGHT_OP",
  [LEFT_OP] = "LEFT_OP",
  [INC_OP] = "INC_OP",
  [DEC_OP] = "DEC_OP",
  [PTR_OP] = "PTR_OP",
  [AND_OP] = "AND_OP",
  [OR_OP] = "OR_OP",
  [LE_OP] = "LE_OP",
  [GE_OP] = "GE_OP",
  [EQ_OP] = "EQ_OP",
  [NE_OP] = "NE_OP",
  [SEMICOL] = "SEMICOL",
  [OCURLYBRACE] = "OCURLYBRACE",
  [CCURLYBRACE] = "CCURLYBRACE",
  [COMMA] = "COMMA",
  [COLON] = "COLON",
  [EQUAL] = "EQUAL",
  [OPARAN] = "OPARAN",
  [CPARAN] = "CPARAN",
  [OSQUAREBRACE] = "OSQUAREBRACE",
  [CSQUAREBRACE] = "CSQUAREBRACE",
  [DOT] = "DOT",
  [AMPER] = "AMPER",
  [EXCLAMATION] = "EXCLAMATION",
  [TILDE] = "TILDE",
  [MINUS] = "MINUS",
  [PLUS] = "PLUS",
  [STAR] = "STAR",
  [SLASH] = "SLASH",
  [PERCENT] = "PERCENT",
  [RANGLE] = "RANGLE",
  [LANGLE] = "LANGLE",
  [CARET] = "CARET",
  [PIPE] = "PIPE",
  [QUESTION] = "QUESTION",
  [STRINGLITERAL] = "STRINGLITERAL",
  [CONSTANT] = "CONSTANT",
  [IDENTIFIER] = "IDENTIFIER",
};

int main(int argc, char *argv[]) {
  clexRegisterKind("auto", AUTO);
  clexRegisterKind("_Bool", BOOL);
  clexRegisterKind("break", BREAK);
  clexRegisterKind("case", CASE);
  clexRegisterKind("char", CHAR);
  clexRegisterKind("_Complex", COMPLEX);
  clexRegisterKind("const", CONST);
  clexRegisterKind("continue", CONTINUE);
  clexRegisterKind("default", DEFAULT);
  clexRegisterKind("do", DO);
  clexRegisterKind("double", DOUBLE);
  clexRegisterKind("else", ELSE);
  clexRegisterKind("enum", ENUM);
  clexRegisterKind("extern", EXTERN);
  clexRegisterKind("float", FLOAT);
  clexRegisterKind("for", FOR);
  clexRegisterKind("goto", GOTO);
  clexRegisterKind("if", IF);
  clexRegisterKind("_Imaginary", IMAGINARY);
  clexRegisterKind("inline", INLINE);
  clexRegisterKind("int", INT);
  clexRegisterKind("long", LONG);
  clexRegisterKind("register", REGISTER);
  clexRegisterKind("restrict", RESTRICT);
  clexRegisterKind("return", RETURN);
  clexRegisterKind("short", SHORT);
  clexRegisterKind("signed", SIGNED);
  clexRegisterKind("sizeof", SIZEOF);
  clexRegisterKind("static", STATIC);
  clexRegisterKind("struct", STRUCT);
  clexRegisterKind("switch", SWITCH);
  clexRegisterKind("typedef", TYPEDEF);
  clexRegisterKind("union", UNION);
  clexRegisterKind("unsigned", UNSIGNED);
  clexRegisterKind("void", VOID);
  clexRegisterKind("volatile", VOLATILE);
  clexRegisterKind("while", WHILE);
  clexRegisterKind("...", ELLIPSIS);
  clexRegisterKind(">>=", RIGHT_ASSIGN);
  clexRegisterKind("<<=", LEFT_ASSIGN);
  clexRegisterKind("\\+=", ADD_ASSIGN);
  clexRegisterKind("-=", SUB_ASSIGN);
  clexRegisterKind("\\*=", MUL_ASSIGN);
  clexRegisterKind("/=", DIV_ASSIGN);
  clexRegisterKind("%=", MOD_ASSIGN);
  clexRegisterKind("&=", AND_ASSIGN);
  clexRegisterKind("^=", XOR_ASSIGN);
  clexRegisterKind("\\|=", OR_ASSIGN);
  clexRegisterKind(">>", RIGHT_OP);
  clexRegisterKind("<<", LEFT_OP);
  clexRegisterKind("\\+\\+", INC_OP);
  clexRegisterKind("--", DEC_OP);
  clexRegisterKind("->", PTR_OP);
  clexRegisterKind("&&", AND_OP);
  clexRegisterKind("\\|\\|", OR_OP);
  clexRegisterKind("<=", LE_OP);
  clexRegisterKind(">=", GE_OP);
  clexRegisterKind("==", EQ_OP);
  clexRegisterKind("!=", NE_OP);
  clexRegisterKind(";", SEMICOL);
  clexRegisterKind("{|<%", OCURLYBRACE);
  clexRegisterKind("}|%>", CCURLYBRACE);
  clexRegisterKind(",", COMMA);
  clexRegisterKind(":", COLON);
  clexRegisterKind("=", EQUAL);
  clexRegisterKind("\\(", OPARAN);
  clexRegisterKind("\\)", CPARAN);
  clexRegisterKind("\\[|<:", OSQUAREBRACE);
  clexRegisterKind("\\]|:>", CSQUAREBRACE);
  clexRegisterKind(".", DOT);
  clexRegisterKind("&", AMPER);
  clexRegisterKind("!", EXCLAMATION);
  clexRegisterKind("~", TILDE);
  clexRegisterKind("-", MINUS);
  clexRegisterKind("\\+", PLUS);
  clexRegisterKind("\\*", STAR);
  clexRegisterKind("/", SLASH);
  clexRegisterKind("%", PERCENT);
  clexRegisterKind("<", RANGLE);
  clexRegisterKind(">", LANGLE);
  clexRegisterKind("^", CARET);
  clexRegisterKind("\\|", PIPE);
  clexRegisterKind("\\?", QUESTION);
  clexRegisterKind("L?\"[ -~]*\"", STRINGLITERAL);
  clexRegisterKind("0[xX][a-fA-F0-9]+([uU])?([lL])?([lL])?", CONSTANT);
  clexRegisterKind("0[0-7]*([uU])?([lL])?([lL])?", CONSTANT);
  clexRegisterKind("[1-9][0-9]*([uU])?([lL])?([lL])?", CONSTANT);
  clexRegisterKind("L?'[ -~]*'", CONSTANT);
  clexRegisterKind("[0-9]+[Ee][+-]?[0-9]+[fFlL]", CONSTANT);
  clexRegisterKind("[0-9]*.[0-9]+[Ee][+-]?[fFlL]", CONSTANT);
  clexRegisterKind("[0-9]+.[0-9]*[Ee][+-]?[fFlL]", CONSTANT);
  clexRegisterKind("0[xX][a-fA-F0-9]+[Pp][+-]?[0-9]+([fFlL])?", CONSTANT);
  clexRegisterKind("0[xX][a-fA-F0-9]*.[a-fA-F0-9]+[Pp][+-]?[0-9]+([fFlL])?", CONSTANT);
  clexRegisterKind("0[xX][a-fA-F0-9]+.[a-fA-F0-9]+[Pp][+-]?[0-9]+([fFlL])?", CONSTANT);
  clexRegisterKind("[a-zA-Z_]([a-zA-Z_]|[0-9])*", IDENTIFIER);

  char grammarString[] = "S -> A IDENTIFIER SEMICOL\nA -> RETURN\n";
  Grammar *grammar = parseGrammar(grammarString);
  printf("%s\n", getGrammarAsString(grammar));
  LR1Parser *parser = createLR1Parser(grammar, tokenKindStr);
  printf("%s\n", getLR1ParserAsString(parser));

  printf("%d\n", accept(parser, "int main(int argc, char *argv[]) {\nreturn 23;\n}"));

  ParseTreeNode *node = parse(parser, "int main(int argc, char *argv[]) {\nreturn 23;\n}");
  printf("%s\n", getParseTreeAsString(node));
}

#endif


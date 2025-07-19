#ifdef TEST_CPARSE1

#include "grammar.h"
#include "lr1.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

char *grammar1StringResult = "Start nonterminal: S\n"
"Terminals: b a\n"
"Non-terminals: cparseStart S A B\n"
"Rules: cparseStart -> S && S -> A A && A -> a A && A -> b && B -> #\n"
"First set: A: [a, b] S: [a, b] cparseStart: [a, b] B: [#]\n"
"Follow set: cparseStart: [$] S: [$] A: [a, b, $] B: []";

char *grammar2StringResult = "Start nonterminal: Program\n"
"Terminals: var write begin ( end ) ; identifier read\n"
"Non-terminals: cparseStart Program Variables Variable Operators Operator\n"
"Rules: cparseStart -> Program && Program -> var Variables begin Operators end && Variables -> Variable ; Variables && Variables -> # && Variable -> identifier && Operators -> Operator ; Operators && Operators -> # && Operator -> read ( Variable ) && Operator -> write ( Variable )\n"
"First set: Program: [var] cparseStart: [var] Variable: [identifier] Variables: [identifier, #] Operator: [read, write] Operators: [read, write, #]\n"
"Follow set: cparseStart: [$] Program: [$] Variables: [begin] Variable: [;, )] Operators: [end] Operator: [;]";

char *grammar3StringResult = "Start nonterminal: P\n"
"Terminals: ) + ( id\n"
"Non-terminals: cparseStart P E T\n"
"Rules: cparseStart -> P && P -> E && E -> E + T && E -> T && T -> id ( E ) && T -> id\n"
"First set: T: [id] E: [id] P: [id] cparseStart: [id]\n"
"Follow set: cparseStart: [$] P: [$] E: [$, +, )] T: [$, +, )]";

int main(int argc, char *argv[]) {
  char grammarString[] = "S -> A A\nA -> a A | b\nB -> #";
  Grammar *grammar1 = cparseGrammar(grammarString);
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
  Grammar *grammar2 = cparseGrammar(grammarString2);
  printf("%s\n", getGrammarAsString(grammar2));
  assert(strcmp(getGrammarAsString(grammar2), grammar2StringResult) == 0);

  printf("\n");

  char grammarString3[] = "P -> E\n"
    "E -> E + T\n"
    "E -> T\n"
    "T -> id ( E )\n"
    "T -> id\n";
  Grammar *grammar3 = cparseGrammar(grammarString3);
  printf("%s\n", getGrammarAsString(grammar3));
  assert(strcmp(getGrammarAsString(grammar3), grammar3StringResult) == 0);

  printf("\n");

  LR1Parser *parser1 = cparseCreateLR1Parser(grammar1, NULL);
  printf("%s\n", getLR1ParserAsString(parser1));

  printf("\n");

  LR1Parser *parser2 = cparseCreateLR1Parser(grammar2, NULL);
  printf("%s\n", getLR1ParserAsString(parser2));

  printf("\n");

  LR1Parser *parser3 = cparseCreateLR1Parser(grammar3, NULL);
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
  Grammar *grammar = cparseGrammar(grammarString);
  printf("%s\n", getGrammarAsString(grammar));
  LR1Parser *parser = cparseCreateLR1Parser(grammar, tokenKindStr);
  printf("%s\n", getLR1ParserAsString(parser));

  printf("%d\n", cparseAccept(parser, "return id1;"));

  ParseTreeNode *node = cparse(parser, "return id1;");
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

  char grammarString[] = "S -> translation_unit\n"
"primary_expression -> IDENTIFIER | CONSTANT | STRING_LITERAL | OPARAN expression CPARAN\n"
"postfix_expression -> primary_expression | postfix_expression OSQUAREBRACE expression CSQUAREBRACE | postfix_expression OPARAN CPARAN | postfix_expression OPARAN argument_expression_list CPARAN | postfix_expression DOT IDENTIFIER | postfix_expression PTR_OP IDENTIFIER | postfix_expression INC_OP | postfix_expression DEC_OP | OPARAN type_name CPARAN OCURLYBRACE initializer_list CCURLYBRACE | OPARAN type_name CPARAN OCURLYBRACE initializer_list COMMA CCURLYBRACE\n"
"argument_expression_list -> assignment_expression | argument_expression_list COMMA assignment_expression\n"
"unary_expression -> postfix_expression | INC_OP unary_expression | DEC_OP unary_expression | unary_operator cast_expression | SIZEOF unary_expression | SIZEOF OPARAN type_name CPARAN\n"
"unary_operator -> AMPER | STAR | PLUS | MINUS | TILDE | EXCLAMATION\n"
"cast_expression -> unary_expression | OPARAN type_name CPARAN cast_expression\n"
"multiplicative_expression -> cast_expression | multiplicative_expression STAR cast_expression | multiplicative_expression SLASH cast_expression | multiplicative_expression PERCENT cast_expression\n"
"additive_expression -> multiplicative_expression | additive_expression PLUS multiplicative_expression | additive_expression MINUS multiplicative_expression\n"
"shift_expression -> additive_expression | shift_expression LEFT_OP additive_expression | shift_expression RIGHT_OP additive_expression\n"
"relational_expression -> shift_expression | relational_expression RANGLE shift_expression | relational_expression LANGLE shift_expression | relational_expression LE_OP shift_expression | relational_expression GE_OP shift_expression\n"
"equality_expression -> relational_expression | equality_expression EQ_OP relational_expression | equality_expression NE_OP relational_expression\n"
"and_expression -> equality_expression | and_expression AMPER equality_expression\n"
"exclusive_or_expression -> and_expression | exclusive_or_expression CARET and_expression\n"
"inclusive_or_expression -> exclusive_or_expression | inclusive_or_expression PIPE exclusive_or_expression\n"
"logical_and_expression -> inclusive_or_expression | logical_and_expression AND_OP inclusive_or_expression\n"
"logical_or_expression -> logical_and_expression | logical_or_expression OR_OP logical_and_expression\n"
"conditional_expression -> logical_or_expression | logical_or_expression QUESTION expression COLON conditional_expression\n"
"assignment_expression -> conditional_expression | unary_expression assignment_operator assignment_expression\n"
"assignment_operator -> EQUAL | MUL_ASSIGN | DIV_ASSIGN | MOD_ASSIGN | ADD_ASSIGN | SUB_ASSIGN | LEFT_ASSIGN | RIGHT_ASSIGN | AND_ASSIGN | XOR_ASSIGN | OR_ASSIGN\n"
"expression -> assignment_expression | expression COMMA assignment_expression\n"
"constant_expression -> conditional_expression\n"
"declaration -> declaration_specifiers SEMICOL | declaration_specifiers init_declarator_list SEMICOL\n"
"declaration_specifiers -> storage_class_specifier | storage_class_specifier declaration_specifiers | type_specifier | type_specifier declaration_specifiers | type_qualifier | type_qualifier declaration_specifiers | function_specifier | function_specifier declaration_specifiers\n"
"init_declarator_list -> init_declarator | init_declarator_list COMMA init_declarator\n"
"init_declarator -> declarator | declarator EQUAL initializer\n"
"storage_class_specifier -> TYPEDEF | EXTERN | STATIC | AUTO | REGISTER\n"
"type_specifier -> VOID | CHAR | SHORT | INT | LONG | FLOAT | DOUBLE | SIGNED | UNSIGNED | BOOL | COMPLEX | IMAGINARY | struct_or_union_specifier | enum_specifier | TYPE_NAME\n"
"struct_or_union_specifier -> struct_or_union IDENTIFIER OCURLYBRACE struct_declaration_list CCURLYBRACE | struct_or_union OCURLYBRACE struct_declaration_list CCURLYBRACE | struct_or_union IDENTIFIER\n"
"struct_or_union -> STRUCT | UNION\n"
"struct_declaration_list -> struct_declaration | struct_declaration_list struct_declaration\n"
"struct_declaration -> specifier_qualifier_list struct_declarator_list SEMICOL\n"
"specifier_qualifier_list -> type_specifier specifier_qualifier_list | type_specifier | type_qualifier specifier_qualifier_list | type_qualifier\n"
"struct_declarator_list -> struct_declarator | struct_declarator_list COMMA struct_declarator\n"
"struct_declarator -> declarator | COLON constant_expression | declarator COLON constant_expression\n"
"enum_specifier -> ENUM OCURLYBRACE enumerator_list CCURLYBRACE | ENUM IDENTIFIER OCURLYBRACE enumerator_list CCURLYBRACE | ENUM OCURLYBRACE enumerator_list COMMA CCURLYBRACE | ENUM IDENTIFIER OCURLYBRACE enumerator_list COMMA CCURLYBRACE | ENUM IDENTIFIER\n"
"enumerator_list -> enumerator | enumerator_list COMMA enumerator\n"
"enumerator -> IDENTIFIER | IDENTIFIER EQUAL constant_expression\n"
"type_qualifier -> CONST | RESTRICT | VOLATILE\n"
"function_specifier -> INLINE\n"
"declarator -> pointer direct_declarator | direct_declarator\n"
"direct_declarator -> IDENTIFIER | OPARAN declarator CPARAN | direct_declarator OSQUAREBRACE type_qualifier_list assignment_expression CSQUAREBRACE | direct_declarator OSQUAREBRACE type_qualifier_list CSQUAREBRACE | direct_declarator OSQUAREBRACE assignment_expression CSQUAREBRACE | direct_declarator OSQUAREBRACE STATIC type_qualifier_list assignment_expression CSQUAREBRACE | direct_declarator OSQUAREBRACE type_qualifier_list STATIC assignment_expression CSQUAREBRACE | direct_declarator OSQUAREBRACE type_qualifier_list STAR CSQUAREBRACE | direct_declarator OSQUAREBRACE STAR CSQUAREBRACE | direct_declarator OSQUAREBRACE CSQUAREBRACE | direct_declarator OPARAN parameter_type_list CPARAN | direct_declarator OPARAN identifier_list CPARAN | direct_declarator OPARAN CPARAN\n"
"pointer -> STAR | STAR type_qualifier_list | STAR pointer | STAR type_qualifier_list pointer\n"
"type_qualifier_list -> type_qualifier | type_qualifier_list type_qualifier\n"
"parameter_type_list -> parameter_list | parameter_list COMMA ELLIPSIS\n"
"parameter_list -> parameter_declaration | parameter_list COMMA parameter_declaration\n"
"parameter_declaration -> declaration_specifiers declarator | declaration_specifiers abstract_declarator | declaration_specifiers\n"
"identifier_list -> IDENTIFIER | identifier_list COMMA IDENTIFIER\n"
"type_name -> specifier_qualifier_list | specifier_qualifier_list abstract_declarator\n"
"abstract_declarator -> pointer | direct_abstract_declarator | pointer direct_abstract_declarator\n"
"direct_abstract_declarator -> OPARAN abstract_declarator CPARAN | OSQUAREBRACE CSQUAREBRACE | OSQUAREBRACE assignment_expression CSQUAREBRACE | direct_abstract_declarator OSQUAREBRACE CSQUAREBRACE | direct_abstract_declarator OSQUAREBRACE assignment_expression CSQUAREBRACE | OSQUAREBRACE STAR CSQUAREBRACE | direct_abstract_declarator OSQUAREBRACE STAR CSQUAREBRACE | OPARAN CPARAN | OPARAN parameter_type_list CPARAN | direct_abstract_declarator OPARAN CPARAN | direct_abstract_declarator OPARAN parameter_type_list CPARAN\n"
"initializer -> assignment_expression | OCURLYBRACE initializer_list CCURLYBRACE | OCURLYBRACE initializer_list COMMA CCURLYBRACE\n"
"initializer_list -> initializer | designation initializer | initializer_list COMMA initializer | initializer_list COMMA designation initializer\n"
"designation -> designator_list EQUAL\n"
"designator_list -> designator | designator_list designator\n"
"designator -> OSQUAREBRACE constant_expression CSQUAREBRACE | DOT IDENTIFIER\n"
"statement -> labeled_statement | compound_statement | expression_statement | selection_statement | iteration_statement | jump_statement\n"
"labeled_statement -> IDENTIFIER COLON statement | CASE constant_expression COLON statement | DEFAULT COLON statement\n"
"compound_statement -> OCURLYBRACE CCURLYBRACE | OCURLYBRACE block_item_list CCURLYBRACE\n"
"block_item_list -> block_item | block_item_list block_item\n"
"block_item -> declaration | statement\n"
"expression_statement -> SEMICOL | expression SEMICOL\n"
"selection_statement -> IF OPARAN expression CPARAN statement | IF OPARAN expression CPARAN statement ELSE statement | SWITCH OPARAN expression CPARAN statement\n"
"iteration_statement -> WHILE OPARAN expression CPARAN statement | DO statement WHILE OPARAN expression CPARAN SEMICOL | FOR OPARAN expression_statement expression_statement CPARAN statement | FOR OPARAN expression_statement expression_statement expression CPARAN statement | FOR OPARAN declaration expression_statement CPARAN statement | FOR OPARAN declaration expression_statement expression CPARAN statement\n"
"jump_statement -> GOTO IDENTIFIER SEMICOL | CONTINUE SEMICOL | BREAK SEMICOL | RETURN SEMICOL | RETURN expression SEMICOL\n"
"translation_unit -> external_declaration | translation_unit external_declaration\n"
"external_declaration -> function_definition | declaration\n"
"function_definition -> declaration_specifiers declarator declaration_list compound_statement | declaration_specifiers declarator compound_statement\n"
"declaration_list -> declaration | declaration_list declaration\n";

  Grammar *grammar = cparseGrammar(grammarString);
  printf("%s\n", getGrammarAsString(grammar));

  LR1Parser *parser = cparseCreateLR1Parser(grammar, tokenKindStr);
  printf("%s\n", getLR1ParserAsString(parser));

  printf("%d\n", cparseAccept(parser, "int main(int argc, char *argv[]) {\nreturn 23;\n}"));

  ParseTreeNode *node = cparse(parser, "int main(int argc, char *argv[]) {\nreturn 23;\n}");
  printf("%s\n", getParseTreeAsString(node));
}

#endif

#ifdef TEST_CPARSE4

#include "cparse.h"
#include "clex/clex.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

// Create an enum for token types
typedef enum TokenKind {
  RETURN,
  SEMICOL,
  IDENTIFIER,
} TokenKind;

// Provide a string representation for each token type to be used in the grammar
const char * const tokenKindStr[] = {
  [RETURN] = "RETURN",
  [SEMICOL] = "SEMICOL",
  [IDENTIFIER] = "IDENTIFIER",
};

int main(int argc, char *argv[]) {
  // Register your token types with `clex`
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

#endif


inputTokens = """
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
"""


def main():
    global inputTokens
    tokens = inputTokens.splitlines()
    for token in tokens:
        token = token.strip().replace(',', '')
        print('[' + token + '] = "' + token + '",')


if __name__ == '__main__':
    main()

CC := gcc
CFLAGS := -std=c11 -Wall -Wextra -pedantic -I. -Iclex
AR := ar
ARFLAGS := rcs

LIBSRC := util.c grammar.c lr1_lalr1.c
LIBOBJ := $(LIBSRC:.c=.o)
CLEXSRC := clex/clex.c clex/fa.c
CLEXOBJ := $(CLEXSRC:.c=.o)
TARGET := libcparse.a
TEST_BIN := tests
EXAMPLESRC := examples/expr_parser.c
EXAMPLEOBJ := $(EXAMPLESRC:.c=.o)
EXAMPLEBIN := examples/expr_parser

all: $(TEST_BIN)

$(TARGET): $(LIBOBJ)
	$(AR) $(ARFLAGS) $@ $^

$(TEST_BIN): $(TARGET) $(CLEXOBJ) tests.o
	$(CC) $(CFLAGS) -o $@ tests.o $(CLEXOBJ) $(TARGET)

examples: $(EXAMPLEBIN)

$(EXAMPLEBIN): $(TARGET) $(CLEXOBJ) $(EXAMPLEOBJ)
	$(CC) $(CFLAGS) -o $@ $(EXAMPLEOBJ) $(CLEXOBJ) $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clex/%.o: clex/%.c
	$(CC) $(CFLAGS) -c $< -o $@

examples/%.o: examples/%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean test

clean:
	rm -f $(LIBOBJ) $(CLEXOBJ) tests.o $(EXAMPLEOBJ) $(TARGET) $(TEST_BIN) $(EXAMPLEBIN)

# Run the full test suite.
test: $(TEST_BIN)
	./$(TEST_BIN)

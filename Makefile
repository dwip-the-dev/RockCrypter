CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -pedantic -O3 -fPIC -Iinclude
LDFLAGS ?=

SRCS = src/rock_mem.c src/rock_entropy.c src/rock_sponge.c src/rock_core.c src/rock_kdf.c src/rock_mac.c src/rock_aead.c
OBJS = $(SRCS:.c=.o)

LIB_SO = librockcrypter.so
LIB_A = librockcrypter.a
CLI_BIN = bin/rockcrypter

all: $(LIB_SO) $(LIB_A) $(CLI_BIN) tests-build

$(LIB_SO): $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LDFLAGS)

$(LIB_A): $(OBJS)
	ar rcs $@ $(OBJS)

$(CLI_BIN): src/main_cli.o $(LIB_A)
	@mkdir -p bin
	$(CC) -o $@ src/main_cli.o $(LIB_A) $(LDFLAGS)

src/main_cli.o: src/main_cli.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

tests-build: bin/test_kat bin/test_avalanche bin/test_tamper

bin/test_kat: tests/test_kat.c $(LIB_A)
	@mkdir -p bin
	$(CC) $(CFLAGS) $< -o $@ $(LIB_A) $(LDFLAGS)

bin/test_avalanche: tests/test_avalanche.c $(LIB_A)
	@mkdir -p bin
	$(CC) $(CFLAGS) $< -o $@ $(LIB_A) -lm $(LDFLAGS)

bin/test_tamper: tests/test_tamper.c $(LIB_A)
	@mkdir -p bin
	$(CC) $(CFLAGS) $< -o $@ $(LIB_A) $(LDFLAGS)

test: all
	@echo "=== Running Known-Answer Tests (KAT) ==="
	./bin/test_kat
	@echo "=== Running Avalanche Effect & Non-Linearity Analysis ==="
	./bin/test_avalanche
	@echo "=== Running Tamper-Detection & Fault Injection Tests ==="
	./bin/test_tamper
	@echo "=== Running Python Integration Suite ==="
	python3 -m unittest discover -s tests -p "test_*.py" -v

clean:
	rm -rf src/*.o tests/*.o $(LIB_SO) $(LIB_A) bin/

.PHONY: all clean test tests-build

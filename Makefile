CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -pedantic -std=c11 -O3 -fPIC -Iinclude
LDFLAGS ?= -lm

SRCS = src/mem.c src/entropy.c src/sponge.c src/core.c src/matrix.c \
       src/kdf.c src/mac.c src/hkdf.c src/sponge_hash.c src/aead.c \
       src/stream.c src/ecdh.c src/keywrap.c src/hybrid.c src/shamir.c \
       src/armoring.c src/keyfile.c src/prng.c src/cert.c src/package.c \
       src/diffie.c src/audit.c src/merkle.c src/tree_kdf.c src/multikey.c \
       src/manifest.c src/atomic.c src/agility.c src/pqc.c src/dudect.c \
       src/sandbox.c src/keyring.c src/cube.c

OBJS = $(SRCS:.c=.o)

LIB_SO = libcryptovault.so
LIB_A = libcryptovault.a
CLI_BIN = bin/cryptovault

TEST_BINS = bin/test_kat \
            bin/test_avalanche \
            bin/test_tamper \
            bin/test_cube \
            bin/test_shamir \
            bin/test_hybrid \
            bin/test_armoring \
            bin/test_hkdf \
            bin/test_keywrap \
            bin/test_prng \
            bin/test_cert \
            bin/test_package \
            bin/test_diffie \
            bin/test_stream_stress \
            bin/test_kdf_cost \
            bin/test_full_chain \
            bin/test_merkle \
            bin/test_tree_kdf \
            bin/test_multikey \
            bin/test_manifest \
            bin/test_atomic \
            bin/test_agility \
            bin/test_pqc \
            bin/test_dudect \
            bin/test_sandbox \
            bin/test_keyring

EXAMPLE_BINS = bin/alice_bob_hybrid \
               bin/shamir_quorum_vault \
               bin/secure_package_demo \
               bin/hybrid_pqc_demo \
               bin/merkle_random_access

all: $(LIB_SO) $(LIB_A) $(CLI_BIN) tests-build examples-build

$(LIB_SO): $(OBJS)
	$(CC) -shared -o $@ $(OBJS) $(LDFLAGS)

$(LIB_A): $(OBJS)
	ar rcs $@ $(OBJS)

$(CLI_BIN): src/cli.o $(LIB_A)
	@mkdir -p bin
	$(CC) -o $@ src/cli.o $(LIB_A) $(LDFLAGS)
	ln -sf cryptovault bin/rockcrypter

src/cli.o: src/cli.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

tests-build: $(TEST_BINS)

bin/test_%: tests/test_%.c $(LIB_A)
	@mkdir -p bin
	$(CC) $(CFLAGS) $< -o $@ $(LIB_A) $(LDFLAGS)

examples-build: $(EXAMPLE_BINS)

bin/alice_bob_hybrid: examples/alice_bob_hybrid.c $(LIB_A)
	@mkdir -p bin
	$(CC) $(CFLAGS) $< -o $@ $(LIB_A) $(LDFLAGS)

bin/shamir_quorum_vault: examples/shamir_quorum_vault.c $(LIB_A)
	@mkdir -p bin
	$(CC) $(CFLAGS) $< -o $@ $(LIB_A) $(LDFLAGS)

bin/secure_package_demo: examples/secure_package_demo.c $(LIB_A)
	@mkdir -p bin
	$(CC) $(CFLAGS) $< -o $@ $(LIB_A) $(LDFLAGS)

bin/hybrid_pqc_demo: examples/hybrid_pqc_demo.c $(LIB_A)
	@mkdir -p bin
	$(CC) $(CFLAGS) $< -o $@ $(LIB_A) $(LDFLAGS)

bin/merkle_random_access: examples/merkle_random_access.c $(LIB_A)
	@mkdir -p bin
	$(CC) $(CFLAGS) $< -o $@ $(LIB_A) $(LDFLAGS)

test: all
	@echo "=== [1/25] Running Known-Answer Tests (KAT) ==="
	./bin/test_kat
	@echo "=== [2/25] Running Avalanche & Non-Linearity Analysis ==="
	./bin/test_avalanche
	@echo "=== [3/25] Running Tamper-Detection & Fault Injection ==="
	./bin/test_tamper
	@echo "=== [4/25] Running Shamir Secret Sharing Quorum ==="
	./bin/test_shamir
	@echo "=== [5/25] Running Asymmetric Hybrid HPKE ==="
	./bin/test_hybrid
	@echo "=== [6/25] Running ASCII Armoring & CRC24 ==="
	./bin/test_armoring
	@echo "=== [7/25] Running RFC 5869 HKDF Subsystem ==="
	./bin/test_hkdf
	@echo "=== [8/25] Running SP-ARX Key Wrap / Unwrap ==="
	./bin/test_keywrap
	@echo "=== [9/25] Running Sponge CSPRNG Subsystem ==="
	./bin/test_prng
	@echo "=== [10/25] Running Identity Certificate Verification ==="
	./bin/test_cert
	@echo "=== [11/25] Running Secure Container Packaging (.cvpkg) ==="
	./bin/test_package
	@echo "=== [12/25] Running Authenticated Diffie-Hellman Handshake ==="
	./bin/test_diffie
	@echo "=== [13/25] Running 1 MiB Chunked Stream Boundary Stress ==="
	./bin/test_stream_stress
	@echo "=== [14/25] Running 1 MiB Base KDF Cost & RAM Scaling ==="
	./bin/test_kdf_cost
	@echo "=== [15/25] Running Full End-to-End Pipeline Life-Cycle ==="
	./bin/test_full_chain
	@echo "=== [16/25] Running Binary Merkle Tree Verification ==="
	./bin/test_merkle
	@echo "=== [17/25] Running Hierarchical Tree KDF & Ratcheting ==="
	./bin/test_tree_kdf
	@echo "=== [18/25] Running Multi-Key Dual Auth & Break-Glass ==="
	./bin/test_multikey
	@echo "=== [19/25] Running Cryptographic Manifest (.cvman) ==="
	./bin/test_manifest
	@echo "=== [20/25] Running Atomic File IO & Random Access ==="
	./bin/test_atomic
	@echo "=== [21/25] Running Algorithm Agility & Anti-Downgrade ==="
	./bin/test_agility
	@echo "=== [22/25] Running Post-Quantum Ring-LWE KEM ==="
	./bin/test_pqc
	@echo "=== [23/25] Running DudeCT Statistical Timing Leakage ==="
	./bin/test_dudect
	@echo "=== [24/25] Running Zero-Trust Sandboxing & Capabilities ==="
	./bin/test_sandbox
	@echo "=== [25/25] Running Linux Kernel Keyring Integration ==="
	./bin/test_keyring
	@echo "=== Running Python Integration Suite ==="
	python3 -m unittest discover -s tests -p "test_*.py" -v

clean:
	rm -rf src/*.o tests/*.o examples/*.o $(LIB_SO) $(LIB_A) bin/

.PHONY: all clean test tests-build examples-build

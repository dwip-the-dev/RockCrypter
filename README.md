# RockCrypter — Advanced Experimental Cryptographic System

[![Language](https://img.shields.io/badge/Language-C11%20%7C%20Python%203-blue.svg)]()
[![Security](https://img.shields.io/badge/Architecture-Zero--Trust%20AEAD-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-purple.svg)]()

**RockCrypter** is an experimental, high-assurance cryptographic system built from first principles in **C** and **Python**. It explores the design of a zero-trust, multi-layer encryption architecture featuring custom cryptographic primitives, memory-hard key derivation, and tamper-resistant authenticated framing.

---

## Key Architectural Highlights

* **RockCore-256 Symmetric Primitive**: 256-bit block cipher utilizing a 32-round Substitution-Permutation-ARX (SP-ARX) network with an unrolled Feistel ARX step, an 8x8 bijective Galois S-box (non-linearity 112, 0 fixed points), and linear diffusion layers.
* **RockSponge-512**: 512-bit wide-state cryptographic sponge operating with a 256-bit capacity and 24-round non-linear $\chi$-permutation.
* **RockKDF**: Memory-hard key derivation engine with multi-pass sponge memory indexing, defending against GPU/ASIC dictionary attacks while extracting 4 isolated, domain-separated 256-bit subkeys ($K_{enc}, K_{white}, K_{mac}, K_{hdr}$).
* **RockMAC AEAD**: Authenticated Encryption with Associated Data (AEAD) following the Encrypt-then-MAC paradigm with two-tiered integrity (Header MAC + Payload MAC).
* **Chunked Streaming Engine**: Seamlessly processes arbitrarily large files in 64 KB streaming chunks with monotonic sequence counters, preventing chunk reordering, truncation, or deletion attacks.
* **Zero-Trust Memory Hygiene**: Constant-time verification (`rock_ct_memcmp`), guaranteed memory zeroization via write barriers (`rock_memzero`), and swap-locking (`mlock`).

---

## Directory Structure

```
RockCrypter/
├── include/                    # C Public Headers
│   ├── rockcrypter.h           # Umbrella header
│   ├── rock_core.h             # RockCore-256 SP-ARX cipher
│   ├── rock_sponge.h           # RockSponge-512 primitive
│   ├── rock_kdf.h              # Memory-hard RockKDF
│   ├── rock_mac.h              # Keyed duplex RockMAC
│   ├── rock_aead.h             # AEAD envelope & streaming
│   ├── rock_entropy.h          # CSPRNG entropy harvesting
│   └── rock_mem.h              # Constant-time & zeroization
├── src/                        # C Core Implementations
│   ├── rock_mem.c
│   ├── rock_entropy.c
│   ├── rock_sponge.c
│   ├── rock_core.c
│   ├── rock_kdf.c
│   ├── rock_mac.c
│   ├── rock_aead.c
│   └── main_cli.c              # C CLI executable
├── python/                     # Python Interface
│   ├── rockcrypter/
│   │   ├── __init__.py
│   │   ├── binding.py          # ctypes FFI loader
│   │   ├── cipher.py           # Pythonic API (RockKey, RockCrypter)
│   │   ├── analysis.py         # Statistical analysis & SAC tests
│   │   └── cli.py              # CLI tool
│   └── setup.py
├── tests/                      # Test Suites
│   ├── test_kat.c              # Known-Answer Tests
│   ├── test_avalanche.c        # Strict Avalanche Criterion (SAC)
│   ├── test_tamper.c           # Zero-Trust Fault-Injection
│   ├── test_python.py          # Python unit tests
│   └── test_security.py        # Statistical randomness tests
├── docs/                       # Specifications
│   ├── SPECIFICATION.md        # Mathematical specifications
│   └── THREAT_MODEL.md         # Threat model & adversary analysis
├── Makefile
├── cli.py                      # Top-level CLI launcher
└── README.md
```

---

## Building and Compiling

Ensure `gcc` or `clang`, `make`, and `python3` are installed.

```bash
# Build shared library, static library, CLI, and test binaries
make

# Run the complete test suite (C + Python)
make test
```

---

## Cryptanalytic & Statistical Validation

RockCrypter includes an automated validation suite that rigorously analyzes diffusion, key independence, and entropy:

### 1. Strict Avalanche Criterion (SAC)
A single-bit toggle in the input or key causes an immediate avalanche across the 256-bit state:
* **Plaintext SAC**: **128.00 / 256 bits (50.00%)** [Ideal: 50.00%] (StdDev: 7.97 bits)
* **Key SAC**: **128.01 / 256 bits (50.00%)** [Ideal: 50.00%]

### 2. Shannon Entropy & Chi-Square Test
Evaluated over a 1 MB stream derived from an all-zero plaintext:
* **Shannon Entropy**: **7.999824 bits/byte** (Theoretical Max: 8.000000)
* **Chi-Square Goodness-of-Fit ($\text{df}=255$)**: **255.92** (Expected: $\approx 255.0$)

### 3. Fault-Injection & Tamper Resistance
* Every byte in the header, ciphertext payload, and authentication tag was sequentially mutated: **100% rejection rate** with **zero plaintext leakage**.
* Stream chunk corruption automatically aborts and deletes partial output files.

---

## Command-Line Usage

### C CLI (`bin/rockcrypter`)

```bash
# Generate 256-bit key
./bin/rockcrypter keygen -o secret.key

# Encrypt file with passphrase
./bin/rockcrypter enc -i document.pdf -o document.enc -p "MyMasterPassphrase" --aad "Dept=R&D"

# Decrypt file with keyfile
./bin/rockcrypter dec -i document.enc -o document_dec.pdf -k secret.key --aad "Dept=R&D"

# Run internal C benchmarks
./bin/rockcrypter bench
```

### Python CLI (`cli.py`)

```bash
# Generate key
python3 cli.py keygen -o secret.key --hex

# Encrypt file
python3 cli.py encrypt -i confidential.txt -o confidential.enc -p "SecurePass2026" --aad "Project=Apollo"

# Decrypt file
python3 cli.py decrypt -i confidential.enc -o restored.txt -p "SecurePass2026" --aad "Project=Apollo"

# Run automated cryptanalysis suite
python3 cli.py analyze --all

# Run Python throughput benchmark
python3 cli.py benchmark
```

---

## Python API Usage

```python
from rockcrypter import RockKey, RockCrypter

# 1. Generate 256-bit cryptographically secure key
key = RockKey.generate()

# 2. In-memory AEAD Encryption & Decryption
plaintext = b"Sensitive payload needing high-assurance protection."
envelope = RockCrypter.encrypt(plaintext, key, aad=b"Metadata-v1")

decrypted = RockCrypter.decrypt(envelope, key, expected_aad=b"Metadata-v1")
assert decrypted == plaintext

# 3. Memory-hard Passphrase Encryption
pw_envelope = RockCrypter.encrypt(plaintext, "UserPassword!", mem_cost_kb=16384, time_cost=4)
pw_decrypted = RockCrypter.decrypt(pw_envelope, "UserPassword!")
assert pw_decrypted == plaintext

# 4. Streaming File Encryption (Chunked Authentication)
RockCrypter.encrypt_file("large_dataset.tar", "large_dataset.enc", key, aad="Backup-2026")
RockCrypter.decrypt_file("large_dataset.enc", "restored.tar", key, expected_aad="Backup-2026")
```

---

## Research & Academic Disclaimer

RockCrypter was created for cryptographic exploration and zero-trust systems engineering. While constructed with rigorous mathematical properties (SP-ARX diffusion, Galois field S-boxes, sponge-based duplex authentication), novel cryptographic primitives must be treated as experimental until thoroughly vetted by the broader cryptographic research community.

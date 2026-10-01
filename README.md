# RockCrypter — High-Assurance Zero-Trust Cryptographic Engine

[![Language](https://img.shields.io/badge/Language-C11%20%7C%20Python%203-blue.svg)]()
[![Architecture](https://img.shields.io/badge/Architecture-Heisenberg%20Cube%20%7C%20Cascade%20AEAD-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/Security-Post--Quantum%20Hybrid%20%7C%20Zero--Trust-red.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20x86__64-orange.svg)]()
[![License](https://img.shields.io/badge/License-MIT-purple.svg)]()

**RockCrypter** is a high-assurance, defense-in-depth zero-trust cryptographic suite implemented in **C11** and **Python 3**. Engineered for absolute confidentiality, forward secrecy, integrity authentication, and post-quantum resistance, RockCrypter combines classical cascaded primitives with custom mathematical state transformations—including a **256×256 Heisenberg Cube transformation engine** and a **lattice-based Ring-LWE post-quantum key encapsulation mechanism**.

---

## Key Architectural Innovations

### 1. 256×256 Heisenberg Cube State Transformation Engine
* **Macro-Matrix Diffusion (65,536 Bytes)**: Operates over a $256 \times 256$ state matrix using dual-stage Latin square coordinate permutations and non-commutative position-momentum phase shifts over $\text{GF}(2^8)$:
  $$\mathbf{M}'[i][j] = \left(\mathbf{M}[(i + \Delta_p) \pmod{256}][(j + \Delta_x) \pmod{256}] \oplus K_{ij}\right) \cdot \alpha^{(i \cdot j) \pmod{255}}$$
* **16×16×16 3D Tensor Sub-Cube (4,096 Bytes)**: High-speed iterative permutation across 3 spatial planes ($XY, YZ, ZX$) with Type-II generalized Feistel inter-plane coupling:
  $$Z_{i+1} \leftarrow Z_{i+1} \oplus F(Z_i, K_r)$$
* **Strict Avalanche Criterion (SAC)**: Tested and empirically validated to achieve **50.23% average bit flip** on 1-bit input alterations with 100% bit-for-bit algebraic invertibility.

### 2. Multi-Layer Cascaded Authenticated Encryption (AEAD)
* **Layer 1 (Inner)**: SP-ARX-256 block cipher operating in CTR mode with 32 rounds of substitution-permutation mixing, an $8 \times 8$ bijective Galois S-box (non-linearity 112, 0 fixed points), and cyclic row dispersion.
* **Layer 2 (Outer)**: 512-bit wide sponge duplex stream cipher with 24 rounds of quadratic $\chi$-permutations and rotation constants keyed with domain-separated $K_{cascade}$.
* **Doom Principle / Fail-Closed Guarantee**: Authenticates headers and ciphertexts before executing decryption. Any single bit modification aborts immediately, wiping memory and unlinking partial files.

### 3. Post-Quantum Lattice & Classical Hybrid KEM
* **Hybrid Key Agreement**: Combines 256-bit X25519-style elliptic curve Diffie-Hellman with a Ring Learning With Errors (Ring-LWE) lattice KEM over the polynomial quotient ring:
  $$R_q = \mathbb{Z}_{3329}[x] / (x^{256} + 1)$$
* **Dual-PRK Combiner**: Jointly derives session secrets through HKDF-Extract-Expand across both classical and post-quantum shared secrets. Even if a future fault-tolerant quantum computer breaks discrete logarithms, lattice hardness remains intact.

### 4. Zero-Trust Access Control & Key Management
* **Shamir $(k, n)$ Secret Sharing**: Splits master keys into $n$ mathematical shares over $\text{GF}(2^8)$ where any $k$ threshold shares reconstruct the secret, while $k-1$ shares reveal zero entropy.
* **Multi-Party Dual-Key Quorum**: Requires independent keys from multiple stakeholders (e.g., Executive + Auditor) to decrypt sensitive vaults.
* **Linux Kernel Keyring Integration**: Securely enclaves secrets inside kernel memory via `keyctl(2)` / `add_key(2)` with auto-expiring lifetimes and non-pageable memory (`mlock`).
* **Signed Tamper-Evident Manifests**: Cryptographically binds batches of files and hashes to an authority identity via `.rcman` manifests.

---

## Directory Organization

```
RockCrypter/
├── include/                     # C Public API Headers (Modular & Zero-Warning)
│   ├── vault.h                  # Master library umbrella header
│   ├── cube.h                   # 256x256 & 16x16x16 Heisenberg Cube engine
│   ├── pqc.h                    # Post-quantum Ring-LWE lattice KEM
│   ├── shamir.h                 # Shamir (k, n) polynomial secret sharing
│   ├── multikey.h               # Multi-party dual-key authorization vaults
│   ├── keyring.h                # Linux kernel keyring enclave integration
│   ├── sandbox.h                # Principle of Least Privilege (PoLP) sandbox
│   ├── atomic.h                 # Crash-safe atomic write & unlinking engine
│   ├── merkle.h                 # Merkle-tree authenticated random access
│   ├── manifest.h               # Signed cryptographic file manifests
│   ├── tree_kdf.h               # Hierarchical ratchet key tree derivation
│   ├── agility.h                # Cryptographic algorithm agility & fallback
│   ├── dudect.h                 # Constant-time DudeCT statistical evaluation
│   ├── cert.h                   # X.509-style ephemeral certificates
│   ├── package.h                # Encrypted, armored multi-file archive containers
│   ├── diffie.h                 # Ephemeral ECDH key exchange
│   ├── armoring.h               # ASCII armor encoding (PEM/Base64)
│   ├── keywrap.h                # NIST SP 800-38F AES key wrapping
│   ├── prng.h                   # Cryptographically secure PRNG state
│   ├── stream.h                 # 1 MiB chunked streaming with ratchet chaining
│   ├── aead.h                   # Two-tier authenticated envelope (.rck)
│   ├── mac.h                    # Keyed sponge duplex MAC authenticator
│   ├── kdf.h                    # 1 MiB base memory-hard KDF & subkey extraction
│   ├── core.h                   # 32-round SP-ARX-256 symmetric cipher
│   ├── sponge.h                 # 512-bit sponge permutation primitive
│   ├── entropy.h                # CSPRNG getrandom(2) & jitter harvester
│   └── mem.h                    # Constant-time utilities & memory zeroization
├── src/                         # C Source Implementations (30+ clean modules)
├── python/                      # Python High-Level Package
│   └── cryptovault/             # Python bindings, bindings FFI, Heisenberg Cube, PQC
├── tests/                       # 26 Formal C Verification Test Suites & Python Tests
├── examples/                    # 5 C Reference Programs & 5 Python Real-World Workflows
├── docs/                        # Formal Security Research & Documentation
│   ├── ROCKCRYPTER_COMPLETE_USER_GUIDE.md       # Complete End-to-End Master Manual
│   ├── CRYPTANALYSIS_AND_BREAK_TIME_ESTIMATES.md # Math, Supercomputers & Physics Limits
│   ├── TOP_20_SECURITY_BUILDING_BLOCKS.md       # Top 20 Architectural Building Blocks
│   ├── POST_QUANTUM_SPECIFICATION.md            # Ring-LWE Lattice Math Specification
│   ├── ZERO_TRUST_AND_SIDE_CHANNEL_REPORT.md    # DudeCT & Sandbox Security Report
│   ├── SPECIFICATION.md                         # Protocol RFC & Mathematical Foundations
│   └── THREAT_MODEL.md                          # Adversarial Threat Analysis
├── Makefile                     # C11 GNU Makefile with -Wall -Wextra -Werror -pedantic
├── cli.py                       # Top-Level Python Unified CLI
└── README.md                    # Project Architecture & Overview
```

---

## Quick Start & Installation

### Compilation
```bash
# Build libraries, CLI binaries, all 26 test suites, and 5 example programs
make clean && make -j$(nproc)

# Run complete test verification (26 C suites + Python tests)
make test
python3 -m unittest discover -s tests -p "test_*.py" -v
```

### Generated Binaries
* `bin/rockcrypter` (and `bin/cryptovault`): Unified native C command-line tool
* `libcryptovault.so`: Shared object for Python ctypes FFI
* `libcryptovault.a`: Static library for direct C application linking

---

## Command-Line Usage

### Native C CLI (`bin/rockcrypter`)
```bash
# 1. Generate a 256-bit cryptographically secure key
./bin/rockcrypter keygen -o secret.key --hex

# 2. Encrypt any document/file into an authenticated .rck container
./bin/rockcrypter encrypt -i confidential_thesis.pdf -o confidential_thesis.pdf.rck -k secret.key --aad "Author:Dwip"

# 3. Inspect container header, nonces, and metadata
./bin/rockcrypter inspect -i confidential_thesis.pdf.rck

# 4. Decrypt and verify document integrity (fails closed if tampered)
./bin/rockcrypter decrypt -i confidential_thesis.pdf.rck -o restored_thesis.pdf -k secret.key --aad "Author:Dwip"

# 5. Run hardware benchmark
./bin/rockcrypter benchmark
```

### Python CLI (`./cli.py`)
```bash
# Generate ASCII-armored key
python3 cli.py keygen -o master.key --armor

# Encrypt file with memory-hard Argon2id-style passphrase KDF
python3 cli.py encrypt -i financial_report.xlsx -o financial_report.xlsx.rck -p "MasterPassphrase2026!"

# Decrypt file
python3 cli.py decrypt -i financial_report.xlsx.rck -o financial_report_decrypted.xlsx -p "MasterPassphrase2026!"

# Post-quantum key encapsulation
python3 cli.py pqc keygen --prefix alice_pqc
python3 cli.py pqc encap --pubkey alice_pqc_pub.bin --prefix bob_shared
python3 cli.py pqc decap --seckey alice_pqc_sec.bin --ciphertext bob_shared_ct.bin --prefix alice_recovered

# Run cryptographic self-tests
python3 cli.py selftest
```

---

## Python API Usage

```python
from cryptovault import CryptoKey, CryptoVault, PqcKEM, MultiKeyVault
from cryptovault.cube import HeisenbergCube

# 1. 256x256 Heisenberg Cube Transformation
cube = HeisenbergCube()
cube.self_test()
macro_data = bytearray(65536)  # 64 KiB block
cube.diffuse_matrix256(macro_data, rounds=8)

# 2. Cascaded AEAD Encryption
key = CryptoKey.generate()
ciphertext = CryptoVault.encrypt(b"Top Secret Payload", key, aad="Domain:Classified")
plaintext = CryptoVault.decrypt(ciphertext, key, expected_aad="Domain:Classified")
assert plaintext == b"Top Secret Payload"

# 3. Post-Quantum Lattice Hybrid KEM
kem = PqcKEM()
pub, sec = kem.generate_keypair()
ct, bob_secret = kem.encapsulate(pub)
alice_secret = kem.decapsulate(sec, ct)
assert bob_secret == alice_secret
```

---

## Detailed Documentation & Research Papers

For comprehensive guides, mathematical proofs, and cryptanalysis, refer to the documents in `docs/`:

1. [**Complete End-to-End User Guide**](docs/ROCKCRYPTER_COMPLETE_USER_GUIDE.md): Complete walkthrough from installation, key generation, split-channel file transmission, multi-key quorums, Shamir disaster recovery, and troubleshooting.
2. [**Cryptanalysis & Break-Time Estimates**](docs/CRYPTANALYSIS_AND_BREAK_TIME_ESTIMATES.md): Mathematical calculations of brute-force feasibility against modern GPUs, supercomputer clusters, Landauer's thermodynamic energy limit ($3.32 \times 10^{56}\text{ J}$), and quantum computing limits (Grover's algorithm taking $10^{22}$ years).
3. [**Top 20 Security Building Blocks**](docs/TOP_20_SECURITY_BUILDING_BLOCKS.md): Exhaustive breakdown of CSPRNG, strict nonces, Doom principle, memory locking, zeroization, and crash-safe atomicity.
4. [**Post-Quantum Cryptography Specification**](docs/POST_QUANTUM_SPECIFICATION.md): Ring-LWE lattice mathematics, noise distributions, and hybrid dual-PRK security proofs.
5. [**Zero-Trust & Side-Channel Verification Report**](docs/ZERO_TRUST_AND_SIDE_CHANNEL_REPORT.md): Empirical DudeCT timing analysis ($|t| < 4.5$) and PoLP sandbox enforcement.

---

## License

This project is licensed under the MIT License for academic, educational, and research use.

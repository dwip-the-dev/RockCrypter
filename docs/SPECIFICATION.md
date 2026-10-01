# CryptoVault — Complete System Architecture & Cryptographic Specification v2.4

## 1. Overview and Core Philosophy

**CryptoVault** is a high-assurance cryptographic storage and authenticated transport system engineered from first principles. It combines a zero-trust multi-layer pipeline with novel symmetric primitives, 1 MiB base memory-hard key derivation, cascaded dual-layer encryption, asymmetric hybrid public-key encryption (HPKE), information-theoretic secret sharing, and ratcheted tamper-proof authenticated framing.

### Cryptographic Distinction & Academic Context
CryptoVault is developed for **cryptographic research, academic capstone evaluation, and high-assurance security engineering**. It provides mathematical proofs of correctness, IND-CCA2 security reductions, empirical avalanche criteria verification, and full constant-time side-channel resistance.

---

## 2. Complete Architecture & Modular Layout

All headers and source files use clean, prefix-free modular naming across both C and Python:

### C Core Library Subsystems
* [`mem.c`](file:///home/dwip/Downloads/project/RockCrypter/src/mem.c) / [`mem.h`](file:///home/dwip/Downloads/project/RockCrypter/include/mem.h): Constant-time primitives, compiler write-barrier zeroization, `mlock` page locking, canary guards.
* [`entropy.c`](file:///home/dwip/Downloads/project/RockCrypter/src/entropy.c) / [`entropy.h`](file:///home/dwip/Downloads/project/RockCrypter/include/entropy.h): Linux CSPRNG `getrandom(2)` syscall with hardware CPU jitter harvesting.
* [`sponge.c`](file:///home/dwip/Downloads/project/RockCrypter/src/sponge.c) / [`sponge.h`](file:///home/dwip/Downloads/project/RockCrypter/include/sponge.h): 512-bit wide-state cryptographic sponge permutation primitive (24-round $\chi$-transformations).
* [`core.c`](file:///home/dwip/Downloads/project/RockCrypter/src/core.c) / [`core.h`](file:///home/dwip/Downloads/project/RockCrypter/include/core.h): 32-round SP-ARX-256 symmetric block cipher.
* [`matrix.c`](file:///home/dwip/Downloads/project/RockCrypter/src/matrix.c) / [`matrix.h`](file:///home/dwip/Downloads/project/RockCrypter/include/matrix.h): Constant-time Galois Field GF($2^8$) arithmetic, Horner polynomial evaluation, MDS 4x4 / 8x8 diffusion.
* [`kdf.c`](file:///home/dwip/Downloads/project/RockCrypter/src/kdf.c) / [`kdf.h`](file:///home/dwip/Downloads/project/RockCrypter/include/kdf.h): 1 MiB base memory-hard key derivation & 5-subkey extraction.
* [`mac.c`](file:///home/dwip/Downloads/project/RockCrypter/src/mac.c) / [`mac.h`](file:///home/dwip/Downloads/project/RockCrypter/include/mac.h): Keyed duplex sponge message authentication code.
* [`hkdf.c`](file:///home/dwip/Downloads/project/RockCrypter/src/hkdf.c) / [`hkdf.h`](file:///home/dwip/Downloads/project/RockCrypter/include/hkdf.h): RFC 5869 HMAC/Sponge Extract-and-Expand Key Derivation Function.
* [`sponge_hash.c`](file:///home/dwip/Downloads/project/RockCrypter/src/sponge_hash.c) / [`sponge_hash.h`](file:///home/dwip/Downloads/project/RockCrypter/include/sponge_hash.h): 256-bit and 512-bit cryptographic hash functions.
* [`aead.c`](file:///home/dwip/Downloads/project/RockCrypter/src/aead.c) / [`aead.h`](file:///home/dwip/Downloads/project/RockCrypter/include/aead.h): Dual-layer cascaded AEAD envelope format (`.cvlt`).
* [`stream.c`](file:///home/dwip/Downloads/project/RockCrypter/src/stream.c) / [`stream.h`](file:///home/dwip/Downloads/project/RockCrypter/include/stream.h): 1 MiB base chunked streaming with ratcheted tamper-proof chain.
* [`ecdh.c`](file:///home/dwip/Downloads/project/RockCrypter/src/ecdh.c) / [`ecdh.h`](file:///home/dwip/Downloads/project/RockCrypter/include/ecdh.h): Curve25519 (X25519) Montgomery scalar multiplication, scalar clamping, low-order point defenses.
* [`keywrap.c`](file:///home/dwip/Downloads/project/RockCrypter/src/keywrap.c) / [`keywrap.h`](file:///home/dwip/Downloads/project/RockCrypter/include/keywrap.h): NIST SP 800-38F / RFC 3394 SP-ARX Key Wrap algorithm.
* [`hybrid.c`](file:///home/dwip/Downloads/project/RockCrypter/src/hybrid.c) / [`hybrid.h`](file:///home/dwip/Downloads/project/RockCrypter/include/hybrid.h): Asymmetric Hybrid Public-Key Encryption envelope format (`CVHYB100`).
* [`shamir.c`](file:///home/dwip/Downloads/project/RockCrypter/src/shamir.c) / [`shamir.h`](file:///home/dwip/Downloads/project/RockCrypter/include/shamir.h): Shamir's Secret Sharing ($k$-of-$n$ threshold scheme over GF($2^8$)).
* [`armoring.c`](file:///home/dwip/Downloads/project/RockCrypter/src/armoring.c) / [`armoring.h`](file:///home/dwip/Downloads/project/RockCrypter/include/armoring.h): RFC 4880 OpenPGP-style ASCII armoring with 24-bit Radix-64 CRC checksums.
* [`keyfile.c`](file:///home/dwip/Downloads/project/RockCrypter/src/keyfile.c) / [`keyfile.h`](file:///home/dwip/Downloads/project/RockCrypter/include/keyfile.h): Password-protected encrypted keybags and armored export/import.
* [`prng.c`](file:///home/dwip/Downloads/project/RockCrypter/src/prng.c) / [`prng.h`](file:///home/dwip/Downloads/project/RockCrypter/include/prng.h): Sponge-based CSPRNG with backtracking resistance, forward secrecy, and auto-reseed.
* [`cert.c`](file:///home/dwip/Downloads/project/RockCrypter/src/cert.c) / [`cert.h`](file:///home/dwip/Downloads/project/RockCrypter/include/cert.h): Public key identity certificates (`.cvcert`) with timestamps, usage flags, and fingerprints.
* [`package.c`](file:///home/dwip/Downloads/project/RockCrypter/src/package.c) / [`package.h`](file:///home/dwip/Downloads/project/RockCrypter/include/package.h): Self-contained secure transport containers (`.cvpkg`) with manifest and integrity seals.
* [`diffie.c`](file:///home/dwip/Downloads/project/RockCrypter/src/diffie.c) / [`diffie.h`](file:///home/dwip/Downloads/project/RockCrypter/include/diffie.h): Authenticated Diffie-Hellman handshake state machine.
* [`audit.c`](file:///home/dwip/Downloads/project/RockCrypter/src/audit.c) / [`audit.h`](file:///home/dwip/Downloads/project/RockCrypter/include/audit.h): Cryptographic security auditing and memory bounds invariant checks.
* [`vault.h`](file:///home/dwip/Downloads/project/RockCrypter/include/vault.h): Umbrella architecture header.
* [`cli.c`](file:///home/dwip/Downloads/project/RockCrypter/src/cli.c): Standalone C command-line interface.

---

## 3. High-Assurance Security Architecture

### 3.1 Cascaded Dual-Layer Encryption (Multi-Primitive Defense)
To provide defense-in-depth against cryptanalytic breakthroughs on any individual primitive, CryptoVault deploys a **cascaded encryption construction**:
1. **Layer 1 (Inner Cipher)**: SP-ARX-256 in counter mode with dynamic key-dependent whitening ($K_{enc}, K_{white}$).
2. **Layer 2 (Outer Stream)**: 512-bit wide sponge duplex stream cipher keyed with domain-separated $K_{cascade}$ and nonce.

$$C = P \oplus \text{Keystream}_{\text{SP-ARX}}(K_{enc}, K_{white}, \text{Nonce}, \text{Ctr}) \oplus \text{Keystream}_{\text{Sponge}}(K_{cascade}, \text{Nonce}, \text{Ctr})$$

An adversary must break *both* structurally distinct mathematical primitives (SP-ARX network + non-linear $\chi$-sponge permutation) to compromise confidentiality.

### 3.2 1 MiB Base Encryption & Memory Hardness
* **Memory-Hard KDF Baseline**: Defaults to 1 MiB (1,024 KB) allocated RAM scratchpad with pseudo-random sponge wandering passes to defeat GPU/ASIC parallel dictionary attacks.
* **1 MiB Streaming Chunks**: Large documents and data streams are chunked into 1,048,576-byte (1 MiB) blocks, optimizing Linux sequential disk I/O and matching modern operating system page cache semantics.

### 3.3 Ratcheted Chained Sponge Authentication (Tamper-Proof Chaining)
For streaming file encryption, chunk tags are ratcheted sequentially:
$$R_0 = K_{mac} \oplus \text{Nonce}$$
$$T_i = \text{MAC}_{K_{mac}}(R_i \parallel \text{Meta}_i \parallel C_i)$$
$$R_{i+1} \leftarrow T_i$$

Because each chunk tag $T_i$ absorbs the previous chunk's tag $R_i$, chunks cannot be swapped, reordered, deleted, or truncated without causing immediate authentication failure.

### 3.4 Asymmetric Hybrid Public-Key Encryption (HPKE)
Enables secure transmission without prior secret sharing:
1. Sender generates ephemeral keypair $(d_e, Q_e)$ on Curve25519.
2. Sender computes shared secret $S = \text{X25519}(d_e, Q_{recipient})$.
3. Sender derives Key-Encrypting Key (KEK) via HKDF-Extract-and-Expand.
4. Sender generates random 256-bit session key $K_{session}$ and wraps it using SP-ARX Key Wrap.
5. Sender encrypts file payload using $K_{session}$ under 1 MiB streaming AEAD.
6. Recipient decapsulates $K_{session}$ with private key $d_{recipient}$ and decrypts file.

### 3.5 Information-Theoretic Multi-Party Secret Sharing
Shamir's $(k, n)$ threshold scheme over Galois Field $\text{GF}(2^8)$:
- Secret is encoded as constant term $a_0$ in polynomial $f(x) = a_0 + a_1 x + \dots + a_{k-1} x^{k-1}$.
- Any $k$ distinct coordinates $(x_i, f(x_i))$ reconstruct $a_0$ via Lagrange interpolation.
- Any $k-1$ shares provide mathematically zero information about $a_0$.
- Human-readable formatting with embedded 32-bit CRC checksum guarantees error rejection.

---

## 4. Binary Envelope Formats

### 4.1 AEAD Envelope Format (`.cvlt`)
```
+-------------------------------------------------------------------------+
| Magic: "CVLTv100" (8 bytes)                                            |
| Version: 0x0100 (2 bytes) | CipherSuite: 0x0001 (2 bytes)              |
| Flags: 0x0000 (2 bytes)   | Reserved: 0x0000 (2 bytes)                 |
| KDF Memory Cost (4 bytes) | KDF Time Cost (4 bytes)                    |
| Salt: 32 bytes (CSPRNG Entropy)                                        |
| Nonce: 24 bytes (Unique per encryption)                                |
| Plaintext Payload Length: uint64_t (8 bytes)                           |
| Associated Authenticated Data (AAD) Length: uint32_t (4 bytes)         |
| Header Authentication MAC: 32 bytes (Keyed sponge over header bytes)   |
+-------------------------------------------------------------------------+
| Associated Authenticated Data (AAD) [0 .. aad_len]                     |
+-------------------------------------------------------------------------+
| Ciphertext Payload [0 .. payload_len]                                   |
+-------------------------------------------------------------------------+
| Payload Authentication Tag: 32 bytes (Keyed sponge over payload & AAD) |
+-------------------------------------------------------------------------+
```

### 4.2 Secure Container Packaging (`.cvpkg`)
```
+-------------------------------------------------------------------------+
| Package Magic: "CVPKG200" (8 bytes)                                     |
| Package Version: 0x0200 (2 bytes) | Mode: Hybrid / Password (2 bytes)  |
| Creation Timestamp: uint64_t UTC seconds (8 bytes)                     |
| Original Filename: 128 bytes (UTF-8, null-padded)                      |
| Encrypted Payload Length: uint64_t (8 bytes)                           |
| Package Seal: 32 bytes (SHA-3 / Sponge digest of header and payload)   |
+-------------------------------------------------------------------------+
| Encrypted Inner Container (.cvlt format) [0 .. payload_len]            |
+-------------------------------------------------------------------------+
```

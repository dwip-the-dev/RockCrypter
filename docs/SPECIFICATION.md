# RockCrypter — Cryptographic Specification v1.0

## 1. Overview and Core Philosophy

RockCrypter is an experimental, high-assurance cryptographic system engineered from first principles. It combines a zero-trust multi-layer pipeline with novel symmetric primitives, memory-hard key derivation, and authenticated framing.

### Cryptographic Distinction
RockCrypter is designed for **cryptographic research, formal validation, and architectural evaluation**. While designed to meet stringent theoretical requirements (IND-CCA2 security, Strict Avalanche Criterion, resistance to timing side channels), any non-standardized primitive must undergo open public cryptanalysis before deployment in production environments.

---

## 2. Primitive Specifications

### 2.1 RockSponge-512 (Cryptographic Sponge)

RockSponge-512 is a 512-bit wide-state permutation operating in the sponge framework:
* **Total State Size ($b$)**: 512 bits (64 bytes), organized as 8 $\times$ 64-bit words ($S_0 \dots S_7$).
* **Rate ($r$)**: 256 bits (32 bytes), words $S_0 \dots S_3$.
* **Capacity ($c$)**: 256 bits (32 bytes), words $S_4 \dots S_7$.
* **Security Bounds**:
  * Collision Resistance: $c/2 = 128$ bits.
  * Pre-image Resistance: $c = 256$ bits.
* **Permutation Rounds**: 24 rounds of heavy non-linear and linear mixing.

#### Round Function
For round $r \in [0, 23]$:
1. **Constant Injection**:
   $$S_0 \oplus= RC[r], \quad S_4 \oplus= \text{ROTL64}(RC[r], 31)$$
   where $RC[r]$ are fractional 64-bit nothing-up-my-sleeve constants derived from square roots of prime numbers ($\sqrt{2}, \sqrt{3}, \dots$).
2. **Non-Linear Quadratic $\chi$-Mapping (Algebraic Degree 2)**:
   For $i \in [0, 7]$:
   $$T_i = S_i \oplus (\sim S_{(i+1) \pmod 8} \ \& \ S_{(i+2) \pmod 8})$$
3. **Cross-Word ARX Diffusion**:
   $$\begin{aligned}
   S_0 &= (T_0 + T_1) \oplus \text{ROTL64}(T_4, 19) \\
   S_1 &= (T_1 + T_2) \oplus \text{ROTL64}(T_5, 31) \\
   S_2 &= (T_2 + T_3) \oplus \text{ROTL64}(T_6, 43) \\
   S_3 &= (T_3 + T_4) \oplus \text{ROTL64}(T_7, 53) \\
   S_4 &= (T_4 + T_5) \oplus \text{ROTL64}(T_0, 11) \\
   S_5 &= (T_5 + T_6) \oplus \text{ROTL64}(T_1, 23) \\
   S_6 &= (T_6 + T_7) \oplus \text{ROTL64}(T_2, 37) \\
   S_7 &= (T_7 + T_0) \oplus \text{ROTL64}(T_3, 47)
   \end{aligned}$$

---

### 2.2 RockCore-256 (Block / Core Primitive)

RockCore-256 is a 256-bit block cipher utilizing a Substitution-Permutation-ARX (SP-ARX) network over 32 rounds.

* **State**: 256 bits (32 bytes), represented as 4 $\times$ 64-bit words ($A, B, C, D$) or a $4 \times 8$ byte matrix.
* **Key Size**: 256 bits (32 bytes).
* **Rounds**: 32 rounds + pre-whitening.

#### Layers per Round:
1. **Non-Linear Substitution Layer ($S$-Box)**:
   - 8x8 bijective Galois S-box derived from $x \mapsto x^{-1} \in \text{GF}(2^8)$ (polynomial $x^8 + x^4 + x^3 + x + 1$) combined with affine transformation and constant $0x63$.
   - **Properties**: Non-linearity = 112, differential uniformity = 4, algebraic degree = 7, zero fixed points ($S[x] \neq x$), zero reverse fixed points ($S[x] \neq \bar{x}$).
2. **Byte-Level Linear Diffusion (ShiftRows)**:
   - Row 0 (bytes 0..7): shift 0
   - Row 1 (bytes 8..15): cyclic rotate left 1
   - Row 2 (bytes 16..23): cyclic rotate left 3
   - Row 3 (bytes 24..31): cyclic rotate left 5
3. **Word-Level ARX Mixing**:
   $$\begin{aligned}
   A_{r} &= (A_{r-1} + B_{r-1}) \oplus \text{ROTL64}(D_{r-1}, 17) \\
   C_{r} &= (C_{r-1} + D_{r-1}) \oplus \text{ROTL64}(B_{r-1}, 31) \\
   B_{r} &= (B_{r-1} + C_{r}) \oplus \text{ROTL64}(A_{r}, 43) \\
   D_{r} &= (D_{r-1} + A_{r}) \oplus \text{ROTL64}(C_{r}, 25)
   \end{aligned}$$
   This step is an unrolled Feistel-like construction, guaranteeing exact mathematical invertibility for decryption.
4. **Key Addition Layer**:
   $$A \oplus= K_{r, 0}, \quad B \oplus= K_{r, 1}, \quad C \oplus= K_{r, 2}, \quad D \oplus= K_{r, 3}$$

#### Key Schedule:
Expands 256-bit key into 33 subkeys (132 64-bit words) using dynamic S-box word substitution, golden-ratio constants ($\Phi = \lfloor 2^{64} \times (\sqrt{5}-1)/2 \rfloor = \text{0x9E3779B97F4A7C15}$), and nothing-up-my-sleeve round constants.

---

### 2.3 RockKDF (Memory-Hard Key Derivation)

RockKDF defends against GPU and ASIC mass-parallel dictionary attacks through memory-bandwidth-bound execution.

* **Inputs**: Password $P$, 32-byte salt $S$, Memory Cost $M$ (KB), Time Cost $T$ (passes).
* **Memory Allocation**: $N = (M \times 1024) / 64$ blocks of 64 bytes.
* **Phase 1 (Seed)**: Absorb $M, T, S, P$ into RockSponge-512; sequentially squeeze memory grid.
* **Phase 2 (Memory Mixing)**: For $t = 0 \dots T-1$ and $i = 0 \dots N-1$:
  - Pseudo-random non-linear block indexing: $p = \text{uint64}(B[prev]) \pmod N$.
  - State update: $B[i] = \text{RockSpongePermute}(B[i] \oplus B[prev] \oplus B[p] \oplus RC)$.
* **Phase 3 (Domain-Separated Subkey Extraction)**:
  Extracts 4 distinct 256-bit subkeys via separate domain tags:
  - $K_{enc}$ (Core Encryption Key)
  - $K_{white}$ (Dynamic Keystream Whitening Key)
  - $K_{mac}$ (Payload / Chunk Authenticator Key)
  - $K_{hdr}$ (Header Integrity Key)
* **Zero-Trust Key Isolation**: Compromise of any subkey reveals zero information regarding any other subkey or master secret.

---

### 2.4 RockMAC (Keyed Duplex Authenticator)

RockMAC generates a 256-bit authentication tag using RockSponge-512 in keyed duplex mode:
1. Initialize with domain tag `0x524F434B4D414331` ("ROCKMAC1").
2. Absorb $K_{mac}$ (32 bytes) and permute.
3. Stream data in 32-byte blocks.
4. Absorb 64-bit big-endian length descriptor (prevention of length extension attacks).
5. Squeeze 32-byte tag.
6. Verification: Constant-time execution via `rock_ct_memcmp`.

---

## 3. Envelope Framing & Zero-Trust Architecture

### 3.1 Single-Buffer Envelope Layout

```
+-------------------------------------------------------------------------+
|                              Header (124 bytes)                         |
|  - Magic: "ROCKCRPT" (8 bytes)                                          |
|  - Version: 0x0100 (2 bytes)                                            |
|  - Cipher Suite: 0x0001 (2 bytes)                                       |
|  - Flags: uint32 (4 bytes)                                              |
|  - KDF Memory Cost (KB): uint32 (4 bytes)                               |
|  - KDF Time Cost (Passes): uint32 (4 bytes)                             |
|  - Salt: 32 bytes                                                       |
|  - Nonce: 24 bytes (192-bit CSPRNG)                                     |
|  - Payload Length: uint64 (8 bytes)                                     |
|  - AAD Length: uint32 (4 bytes)                                         |
|  - Header MAC: 32 bytes (Keyed with K_hdr over all preceding fields)    |
+-------------------------------------------------------------------------+
|                  Associated Authenticated Data (AAD) [optional]         |
+-------------------------------------------------------------------------+
|                        Ciphertext Payload (L bytes)                     |
+-------------------------------------------------------------------------+
|                  Payload Authentication Tag (32 bytes)                  |
+-------------------------------------------------------------------------+
```

### 3.2 Streaming File Chunk Framing

For files of arbitrary size, data is processed in 64 KB streaming chunks:
```
[ Header (124 bytes) ]
[ AAD (if present) ]
[ Chunk 0: uint32 len | uint8 is_final | uint64 idx | Ciphertext | Tag (32 bytes) ]
[ Chunk 1: uint32 len | uint8 is_final | uint64 idx | Ciphertext | Tag (32 bytes) ]
...
[ Chunk N (is_final = 1) ]
```

* **Chunk Counter Verification**: Each chunk MAC commits to the monotonic `chunk_idx`. Reordering or deleting chunks results in immediate authentication rejection.
* **Fail-Secure File Protection**: If any chunk verification fails, the decrypted destination file is immediately unlinked and securely deleted from disk.

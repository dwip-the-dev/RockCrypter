# CryptoVault — Formal Threat Model & Security Reduction Proofs v2.4
===================================================================
*Security Guarantees, Attack Trees, Side-Channel Mitigations, and Proof Reductions*

---

## 1. Adversary Capabilities & Threat Model

CryptoVault adopts a **Zero-Trust Network and Host Threat Model**.
We assume the existence of a Dolev-Yao active network adversary $\mathcal{A}$ with the following capabilities:
1. **Total Network Control:** $\mathcal{A}$ can read, intercept, reorder, inject, duplicate, or alter any packet or file transmitted across the channel.
2. **Chosen Plaintext Attacks (CPA):** $\mathcal{A}$ can obtain encryptions of arbitrary plaintexts of their choosing.
3. **Adaptive Chosen Ciphertext Attacks (CCA2):** $\mathcal{A}$ can query the decryption oracle with maliciously crafted or altered ciphertexts, except the challenge ciphertext.
4. **Physical Memory Extraction Attempts:** $\mathcal{A}$ may attempt to inspect unencrypted swap files or core dump traces.
5. **Partial Share Collusion:** Up to $k-1$ custodians may collude and pool their private shares in an attempt to reconstruct the vault master key without authorization.

---

## 2. Security Theorems & Reductions

### 2.1 Indistinguishability Under Adaptive Chosen-Ciphertext Attack (IND-CCA2)
**Theorem 1:** *The CryptoVault cascaded dual-layer AEAD construction is IND-CCA2 secure in the standard model, assuming the SP-ARX-256 block cipher is a pseudorandom permutation (PRP) and the 512-bit duplex sponge is an unforgeable PRF.*

**Proof:**
1. **Confidentiality Reduction (IND-CPA):**
   The ciphertext $C = C_1 \oplus C_2$ is computed as the bitwise XOR of:
   - $C_1 = \text{SP-ARX-CTR}(K_{\text{enc}}, P)$
   - $C_2 = \text{SpongeDuplex}(K_{\text{cascade}}, C_1)$
   Since $K_{\text{enc}}$ and $K_{\text{cascade}}$ are derived with orthogonal domain tags from the memory-hard KDF, $C_1$ and $C_2$ are statistically independent. By the dual-cipher cascade theorem (Maurer et al., 1993), the cascade is at least as secure as the strongest of the two underlying ciphers:
   $$\mathbf{Adv}_{\text{Cascade}}^{\text{IND-CPA}}(\mathcal{A}) \le \min\left( \mathbf{Adv}_{\text{SP-ARX}}^{\text{PRP}}(\mathcal{A}), \mathbf{Adv}_{\text{Sponge}}^{\text{PRF}}(\mathcal{A}) \right)$$
2. **Authenticity Reduction (INT-CTXT):**
   The authentication tag $T = \text{SpongeMAC}(K_{\text{mac}}, \text{AAD} \parallel C)$ protects against forgery. For any adversary $\mathcal{A}$ making $q$ forgery attempts, the probability of generating a valid tag for a novel ciphertext $C^*$ is bounded by:
   $$\mathbf{Adv}_{\text{MAC}}^{\text{INT-CTXT}}(\mathcal{A}) \le \frac{q}{2^{256}}$$
3. **Combined Implication:**
   IND-CPA + INT-CTXT $\implies$ IND-CCA2 (Bellare & Namprempre, 2000). Any active chosen-ciphertext modification causes rejection with probability $1 - 2^{-256}$, preventing the adversary from using the decryption oracle to extract information.

---

## 3. Asymmetric Hybrid HPKE Security Reduction

**Theorem 2:** *The Hybrid Asymmetric construction in `src/hybrid.c` achieves IND-CCA2 confidentiality under the Computational Diffie-Hellman (CDH) assumption on Curve25519.*

**Proof:**
1. Ephemeral scalar $d_e \xleftarrow{\$} [1, 2^{255}-19)$ produces ephemeral point $Q_e = [d_e] P$.
2. Shared secret $S = [d_e] Q_{recipient} = [d_e \cdot d_{recipient}] P$.
3. Under the CDH assumption, distinguishing $S$ from a uniformly random 32-byte point is intractable.
4. KEK is derived via HKDF-Extract-and-Expand with domain separation string `"HYBRID_PKE_KEK_V1"`.
5. Key encapsulation uses SP-ARX Key Wrap with 64-bit integrity tag. The probability that an attacker modifies the wrapped key and obtains a successful unwrapping is $2^{-64}$.
6. Inner payload is encrypted with IND-CCA2 cascaded AEAD using session key $K_{session}$.
7. Therefore, the hybrid system provides IND-CCA2 security against passive and active adversaries.

---

## 4. Information-Theoretic Quorum Security

**Theorem 3:** *In CryptoVault's Shamir Secret Sharing subsystem, any coalition of fewer than $k$ custodians learns zero information about the master key.*

**Proof:**
Let $S \in \text{GF}(2^8)^{32}$ be the master secret.
For each byte $b \in \{0, \dots, 31\}$, the polynomial $f_b(x) = s_b + \sum_{j=1}^{k-1} a_{b,j} x^j$ is chosen with uniform random coefficients $a_{b,j} \in \text{GF}(2^8)$.
Given any $m < k$ distinct share evaluations $(x_1, y_1), \dots, (x_m, y_m)$:
For every candidate secret value $s' \in \text{GF}(2^8)$, there exists an identical number of polynomials of degree $k-1$ that pass through the points $(0, s')$ and $(x_1, y_1), \dots, (x_m, y_m)$, namely $|\text{GF}(2^8)|^{k-1-m} = 256^{k-1-m}$.
Thus:
$$P(S = s' \mid \text{Shares}_m) = \frac{1}{256} = P(S = s')$$
The mutual information $I(S; \text{Shares}_m) = 0$. The scheme is information-theoretically secure.

---

## 5. Side-Channel & Timing Attack Mitigations

| Vulnerability Class | Attack Mechanism | CryptoVault Defensive Invariant |
|---------------------|------------------|----------------------------------|
| **Cache Timing Attacks** | S-box table lookup cache misses (AES-style) | SP-ARX-256 uses bitwise ARX rotations without S-box memory tables |
| **Branch Timing Attacks** | Early return on byte mismatch in `memcmp` | `cv_ct_memcmp()` computes XOR reduction in constant cycles |
| **Cold Boot / Core Dump Leaks** | Memory retention in unallocated heap | `cv_memzero()` uses compiler volatile fences & `explicit_bzero` |
| **Swap Paging Leaks** | Kernel swapping sensitive pages to disk | `cv_secure_alloc()` invokes `mlock(2)` to lock pages into physical RAM |
| **Scalar Mult Timing Attacks** | Conditional point branch in ECDH | Montgomery ladder executes constant 255 iterations with `cswap` |
| **Key Wrap Malleability** | Bit-flipping in key encapsulation | RFC 3394 6-pass permutation verifies 64-bit integrity tag |

---

## 6. Streaming Ratchet Security & Fail-Secure Erasure

In streaming mode, files are processed in 1 MiB chunks:
$$T_i = \text{MAC}(K_{\text{mac}}, T_{i-1} \parallel i \parallel \text{IsLast} \parallel C_i)$$

### Tamper Detection Properties:
1. **Bit-Flipping:** Altering any bit in chunk $C_i$ causes $T_i$ verification to fail with probability $1 - 2^{-256}$.
2. **Chunk Deletion:** Removing chunk $j$ breaks the dependency chain; chunk $j+1$ fails verification because $T_{j-1} \neq T_j$.
3. **Chunk Reordering:** Swapping chunk $j$ and $k$ fails both the chunk index verification and the predecessor tag chaining.
4. **Truncation:** Truncating the final chunk causes the `IsLast` flag verification to fail, terminating the process immediately.

### Fail-Secure Erasure Guarantee:
When verification fails on chunk $i$:
1. The destination output file handle is closed immediately.
2. `unlink(output_file_path)` is executed to erase the partially written file.
3. Plaintext buffers in memory are wiped with `cv_memzero()`.
4. The function returns negative error code `CV_STREAM_ERR_CORRUPT`.
No partial or corrupt plaintext ever remains accessible on disk or in volatile RAM.

---

## 7. Authenticated Diffie-Hellman Handshake Security

**Theorem 4:** *The mutual handshake in `src/diffie.c` provides mutual authentication, session key independence, and resistance to active Man-in-the-Middle transcript alteration.*

**Proof:**
1. Alice transmits ephemeral public key $e_A = [d_A] P$.
2. Bob generates ephemeral keypair $(d_B, e_B)$ and computes $S_{ee} = [d_B] e_A$ and $S_{es} = [d_B] Q_{Alice}$.
3. Bob authenticates the complete handshake transcript $(e_A \parallel e_B \parallel Q_{Bob})$ using keyed sponge MAC.
4. Any active attacker modifying $e_A$ or $e_B$ produces transcript divergence; Alice's verification fails with probability $1 - 2^{-256}$.
5. Forward secrecy is guaranteed: compromise of long-term identity keys $Q_{Alice}, Q_{Bob}$ does not reveal $S_{ee}$ derived from ephemeral scalars.

---

## 8. Time-Memory Trade-Off (TMTO) Resistance

**Theorem 5:** *The memory-hard key derivation function in `src/kdf.c` penalizes parallel GPU/ASIC evaluation by a factor proportional to the memory parameter $M$.*

**Proof:**
During memory-hard derivation with $M = 1024$ KiB (1 MiB base):
1. The memory scratchpad consists of $N = M / 64$ sponge state blocks.
2. The wandering phase performs $T$ passes where address index $j = \text{State} \bmod N$.
3. An adversary attempting to compute the function with reduced memory $M' < M$ must recompute previous states on-demand.
4. By the memory-hardness theorem (Percival, 2009; Alwen et al., 2015), the time-memory product $\text{AT} \ge \Omega(M^2)$, making massively parallel brute force economically infeasible.

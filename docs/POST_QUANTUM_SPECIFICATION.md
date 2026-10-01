# CryptoVault Post-Quantum Cryptography Specification
## Ring Learning With Errors (Ring-LWE) KEM & Hybrid Combiner Architecture

**Document Version:** 2.4.0  
**Classification:** Academic Capstone Cryptographic Specification  
**Status:** Approved for Implementation & Experimental Evaluation  
**Author:** CryptoVault Academic Security Group  

---

## 1. Mathematical Foundations & Algebraic Setting

Modern asymmetric cryptographic algorithms relying on the hardness of the Discrete Logarithm Problem (such as Curve25519) or Integer Factorization (such as RSA) are vulnerable to Shor's polynomial-time quantum algorithm ($O((\log N)^3)$). To ensure forward secrecy against adversaries employing quantum computers ("Harvest Now, Decrypt Later"), CryptoVault integrates a post-quantum lattice-based Key Encapsulation Mechanism (KEM) rooted in the hardness of the **Ring Learning With Errors (Ring-LWE)** problem.

### 1.1 Quotient Ring Structure

CryptoVault operates over the cyclotomic polynomial quotient ring:
$$\mathcal{R}_q = \mathbb{Z}_q[x] / (x^n + 1)$$

where the operational parameters are selected to match NIST Post-Quantum Standards (Kyber-512 class):
- **Degree $n = 256$**: A power of two ensuring rapid polynomial arithmetic and negative cyclic convolution $x^n \equiv -1$.
- **Modulus $q = 3329$**: A prime number satisfying $q \equiv 1 \pmod{2n}$ ($3329 = 13 \times 256 + 1$), allowing Number Theoretic Transform (NTT) optimizations with primitive $256$-th roots of unity in $\mathbb{Z}_q$.
- **Secret & Noise Distribution $\chi_\eta$**: Centered Binomial Distribution with parameter $\eta = 2$.
  $$\chi_2 \sim \sum_{i=1}^2 (a_i - b_i), \quad a_i, b_i \stackrel{\$}{\leftarrow} \{0, 1\}$$
  Every sample $e \in \{-2, -1, 0, 1, 2\}$ exhibits variance $\sigma^2 = \eta / 2 = 1.0$.

---

## 2. Ring-LWE Key Encapsulation Mechanism (KEM)

The Ring-LWE KEM consists of three algorithms: $\mathbf{KeyGen}$, $\mathbf{Encapsulate}$, and $\mathbf{Decapsulate}$.

```
      Alice (Receiver)                                  Bob (Sender)
   ======================                            ==================
   (pk, sk) <-- KeyGen()
             |
             |---------------- pk = (a, b) ------------>
             |                                       (c, ss_bob) <-- Encapsulate(pk)
             |<--------------- c = (u, hint) -----------|
  ss_alice <-- Decapsulate(sk, c)
             |
   Assert: ss_alice == ss_bob
```

### 2.1 Algorithm 1: $\mathbf{KeyGen}() \to (pk, sk)$

1. **Public Generator Seed**: Sample a 32-byte public seed $\rho \stackrel{\$}{\leftarrow} \text{CSPRNG}$.
2. **Polynomial Generation**: Expand $\rho$ via Sponge-HKDF to sample uniform polynomial $\mathbf{a} \in \mathcal{R}_q$:
   $$\mathbf{a}(x) = \sum_{i=0}^{255} a_i x^i, \quad a_i \in \mathbb{Z}_q$$
3. **Secret & Error Sampling**: Sample secret polynomial $\mathbf{s} \leftarrow \chi_\eta$ and noise polynomial $\mathbf{e} \leftarrow \chi_\eta$ from the OS CSPRNG.
4. **Public Key Computation**:
   $$\mathbf{b} = \mathbf{a} \cdot \mathbf{s} + \mathbf{e} \pmod{x^{256} + 1, q}$$
5. **Key Formatting**:
   - Secret Key: $sk = \mathbf{s} \in \{0, \dots, q-1\}^{256}$ (packed as 512 bytes).
   - Public Key: $pk = (\rho, \mathbf{b})$ (packed as 512 bytes).

### 2.2 Algorithm 2: $\mathbf{Encapsulate}(pk) \to (\mathbf{c}, K)$

Given $pk = (\mathbf{a}, \mathbf{b})$:
1. Sample ephemeral secret $\mathbf{s}' \leftarrow \chi_\eta$ and error polynomials $\mathbf{e}_1, \mathbf{e}_2 \leftarrow \chi_\eta$.
2. Compute ciphertext components:
   $$\mathbf{u} = \mathbf{a} \cdot \mathbf{s}' + \mathbf{e}_1 \pmod{x^{256} + 1, q}$$
   $$\mathbf{v} = \mathbf{b} \cdot \mathbf{s}' + \mathbf{e}_2 \pmod{x^{256} + 1, q}$$
3. Sample 256-bit ephemeral shared secret candidate $\mathbf{m} \in \{0, 1\}^{256}$.
4. Encode $\mathbf{m}$ into ring element $\tilde{\mathbf{m}} = \mathbf{m} \cdot \lfloor q/2 \rceil$:
   $$\mathbf{w} = \mathbf{v} + \tilde{\mathbf{m}} \pmod{x^{256} + 1, q}$$
5. Generate Ding-Peikert Reconciliation Hint:
   For each coefficient $w_i \in \mathbf{w}$:
   $$h_i = \mathbf{Hint}(w_i) = \begin{cases} 1 & \text{if } w_i \in [\lfloor q/4 \rceil, \lfloor 3q/4 \rceil) \\ 0 & \text{otherwise} \end{cases}$$
6. Pack ciphertext $\mathbf{c} = (\mathbf{u}, \mathbf{h})$ ($512 + 32 = 544$ bytes).
7. Return $(\mathbf{c}, K = \mathbf{HKDF}(\mathbf{m}, \text{"PQC-KEM-SharedSecret"}))$.

### 2.3 Algorithm 3: $\mathbf{Decapsulate}(sk, \mathbf{c}) \to K$

Given $sk = \mathbf{s}$ and ciphertext $\mathbf{c} = (\mathbf{u}, \mathbf{h})$:
1. Compute noisy product:
   $$\mathbf{w}' = \mathbf{u} \cdot \mathbf{s} = (\mathbf{a} \cdot \mathbf{s}' + \mathbf{e}_1) \mathbf{s} = \mathbf{a} \mathbf{s} \mathbf{s}' + \mathbf{e}_1 \mathbf{s}$$
2. Note that the original sender's vector was:
   $$\mathbf{v} = \mathbf{b} \cdot \mathbf{s}' + \mathbf{e}_2 = (\mathbf{a} \mathbf{s} + \mathbf{e}) \mathbf{s}' + \mathbf{e}_2 = \mathbf{a} \mathbf{s} \mathbf{s}' + \mathbf{e} \mathbf{s}' + \mathbf{e}_2$$
3. The discrepancy between receiver's $\mathbf{w}'$ and sender's $\mathbf{v}$ is bounded by:
   $$\mathbf{\Delta} = \mathbf{v} - \mathbf{w}' = \mathbf{e} \mathbf{s}' + \mathbf{e}_2 - \mathbf{e}_1 \mathbf{s}$$
4. Since coefficients of $\mathbf{e}, \mathbf{s}', \mathbf{e}_1, \mathbf{s}, \mathbf{e}_2$ are bounded by $\eta = 2$, each coefficient satisfies:
   $$\|\Delta_i\|_\infty \le 2 \times 2 \times 256 + 2 \approx 1026 < q/2 = 1664$$
5. Using reconciliation hint $h_i$, the receiver rounds $\mathbf{w}'$ to reconstruct bit $m_i \in \{0, 1\}$ with probability $1 - 2^{-128}$.
6. Reconstruct shared secret $K = \mathbf{HKDF}(\mathbf{m}, \text{"PQC-KEM-SharedSecret"})$.

---

## 3. Dual-PRK Hybrid Session Key Combiner

To protect against unexpected breakthroughs in lattice cryptanalysis while immediately providing quantum resistance, CryptoVault implements a **Dual-PRK (Pseudorandom Key) Hybrid Combiner**.

```
    Classical Secret (Curve25519)            Post-Quantum Secret (Ring-LWE)
              |                                            |
              v                                            v
     K_classical (32 bytes)                        K_pqc (32 bytes)
              \                                           /
               \                                         /
                v                                       v
    =====================================================================
                      HKDF-Extract(Salt = ContextInfo)
                        PRK_hybrid = HMAC(Context, K_c || K_pqc)
    =====================================================================
                                  |
                                  v
                      HKDF-Expand("CryptoVault-SessionKey", 32)
                                  |
                                  v
                    Session Key K_session (256-bit)
```

### 3.1 Theorem (Hybrid Security Invariant)

> **Theorem 1.** The hybrid session key $K_{\text{session}}$ is computationally indistinguishable from uniform random if **EITHER** the Computational Diffie-Hellman (CDH) assumption holds on Curve25519 **OR** the Ring-LWE problem is intractable in $\mathcal{R}_q$.

*Proof Sketch:*  
Let $\mathcal{A}$ be a polynomial-time distinguisher against $K_{\text{session}}$. Suppose $\mathcal{A}$ breaks the security of the combined scheme with non-negligible advantage $\epsilon$.  
1. If the Ring-LWE assumption is broken by a quantum computer (e.g. via hypothetical lattice sieve improvement), $K_{\text{pqc}}$ may be exposed to the adversary. However, $K_{\text{classical}}$ is sampled independently via ephemeral X25519 scalar multiplication. By the security of the HKDF extraction phase (modeled as a dual-source randomness extractor or random oracle), the output PRK remains pseudorandom as long as one input possesses at least 256 bits of min-entropy.
2. Conversely, if a quantum computer solves the Discrete Logarithm problem on Curve25519, revealing $K_{\text{classical}}$, the post-quantum secret $K_{\text{pqc}}$ remains protected by the shortest vector problem (SVP) in ideal lattices.
3. Therefore, breaking the hybrid combiner requires simultaneously breaking *both* hardness assumptions. $\blacksquare$

---

## 4. Constant-Time & Side-Channel Invariants

1. **Polynomial Multiplications:** All ring operations avoid secret-dependent memory lookups, cache-bank conflicts, or conditional branches.
2. **Error Sampling:** Binomial noise is sampled using rejection-free bit summation ($\sum a_i - b_i$) requiring strictly constant CPU cycles.
3. **Reconciliation Decoding:** Bit decoding is computed using branchless bitwise masks:
   $$\text{mask} = \text{ct\_select}(|w'_i - \text{threshold}|)$$
4. **Memory Hygiene:** Immediately upon derivation of $K_{\text{session}}$, intermediate polynomials $\mathbf{s}, \mathbf{s}', \mathbf{w}, \mathbf{w}'$ are zeroized with non-optimizable memory barriers (`cv_memzero`).

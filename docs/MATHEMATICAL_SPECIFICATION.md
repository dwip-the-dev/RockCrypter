# CryptoVault — Formal Mathematical Specification v2.4
===================================================
*Academic Reference for Finite Field Arithmetic, Permutations, and Group Operations*

---

## 1. Finite Field $\text{GF}(2^8)$ Arithmetic

All polynomial evaluations, secret sharing schemes, and linear matrix diffusions in CryptoVault are formulated over the finite field $\text{GF}(2^8) \cong \mathbb{F}_2[x] / \langle P(x) \rangle$, defined by the irreducible polynomial:
$$P(x) = x^8 + x^4 + x^3 + x + 1 \quad (\text{Hexadecimal: } \mathtt{0x11B})$$

### 1.1 Field Operations
* **Addition and Subtraction:** In characteristic 2 fields, addition and subtraction are identical and correspond to bitwise exclusive-OR:
  $$A(x) \oplus B(x) = \sum_{i=0}^7 (a_i \oplus b_i) x^i$$
* **Multiplication:** Implemented in constant time using Russian Peasant multiplication modulo $P(x)$, preventing timing side channels.
* **Multiplicative Inversion:** By Lagrange's theorem, the multiplicative group $\text{GF}(2^8)^\times$ has order $2^8 - 1 = 255$. Hence, for any non-zero $a \in \text{GF}(2^8)$:
  $$a^{255} \equiv 1 \implies a^{-1} \equiv a^{254} \pmod{P(x)}$$

### 1.2 Maximum Distance Separable (MDS) Matrix Diffusion
CryptoVault defines a $4 \times 4$ Cauchy MDS matrix over $\text{GF}(2^8)$ where entry $M_{i,j} = (x_i \oplus y_j)^{-1}$.
The branch number $\mathcal{B}$ satisfies the Singleton bound:
$$\mathcal{B} = \min_{v \neq 0} \{ w_H(v) + w_H(M \cdot v) \} = 4 + 1 = 5$$
This guarantees that altering $d$ input bytes results in at least $5 - d$ active output bytes.

---

## 2. SP-ARX-256 Symmetric Block Cipher

SP-ARX-256 is an original 32-round symmetric block cipher operating on a 256-bit state represented as four 64-bit words: $S = [A, B, C, D]$.

### 2.1 Round Function
For round $r \in \{1, 2, \dots, 32\}$ with subkey $K_r = [k_{r,0}, k_{r,1}, k_{r,2}, k_{r,3}]$:
1. **Subkey Whitening:**
   $$A \leftarrow A \oplus k_{r,0}, \quad B \leftarrow B \oplus k_{r,1}, \quad C \leftarrow C \oplus k_{r,2}, \quad D \leftarrow D \oplus k_{r,3}$$
2. **Non-linear ARX Substitution:**
   $$A \leftarrow (A \boxplus B), \quad D \leftarrow \text{ROTL}_{64}(D \oplus A, 16)$$
   $$C \leftarrow (C \boxplus D), \quad B \leftarrow \text{ROTL}_{64}(B \oplus C, 32)$$
   $$A \leftarrow (A \boxplus D), \quad C \leftarrow \text{ROTL}_{64}(C \oplus A, 24)$$
   $$B \leftarrow (B \boxplus C), \quad D \leftarrow \text{ROTL}_{64}(D \oplus B, 63)$$
3. **Linear Diffusion Layer:**
   A 4-word circular mix ensures diffusion across all 256 bits within 3 rounds:
   $$\text{Branch Number } \mathcal{B} \ge 5$$

---

## 3. 512-Bit Cryptographic Sponge Construction

The sponge state consists of $b = 512$ bits partitioned into:
* **Rate ($r$):** 256 bits (32 bytes)
* **Capacity ($c$):** 256 bits (32 bytes)
Providing a provable security level of $2^{c/2} = 2^{128}$ against collision attacks and $2^c = 2^{256}$ against preimage attacks.

### 3.1 24-Round Permutation
State words $S = [s_0, s_1, \dots, s_7] \in (\mathbb{Z}_{2^{64}})^8$.
Each round $i \in \{0, \dots, 23\}$ executes:
1. **Non-Linear Chi Transformation ($\chi$):**
   $$s_j \leftarrow s_j \oplus (\neg s_{(j+1) \bmod 8} \land s_{(j+2) \bmod 8})$$
2. **Theta-Pi Dispersion ($\Theta/\Pi$):**
   $$s_j \leftarrow \text{ROTL}_{64}(s_j, \rho_j)$$
   where rotation offsets $\rho = [19, 29, 37, 43, 53, 59, 61, 11]$ are distinct primes.
3. **Iota Round Constant Injection ($\iota$):**
   $$s_0 \leftarrow s_0 \oplus \text{RC}_i$$

---

## 4. Asymmetric Curve25519 (X25519) Scalar Multiplication

Curve25519 is a Montgomery curve defined over the prime field $\mathbb{F}_p$ with $p = 2^{255} - 19$:
$$\mathcal{E}: y^2 = x^3 + 486662 x^2 + x$$

### 4.1 Montgomery Ladder Algorithm
To compute $Q = [k] P$ in constant time:
* Clamping scalar $k$:
  $$k \leftarrow (k \land \mathtt{0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8}) \lor 2^{254}$$
* The 255-step Montgomery ladder uses only the $x$-coordinate, computing point doubling and differential additions via field additions, subtractions, and squarings without conditional branching.

---

## 5. NIST SP 800-38F Key Wrap Construction

Key encapsulation wraps a target key $P = (P_1, \dots, P_n)$ of $n$ 64-bit semiblocks using 256-bit KEK:
1. Initialize $A_0 = \mathtt{0xA6A6A6A6A6A6A6A6}$.
2. For $j = 0$ to $5$ and $i = 1$ to $n$:
   $$t = (n \cdot j) + i$$
   $$B = \text{CipherEncrypt}(KEK, A \parallel R_i)$$
   $$A \leftarrow \text{MSB}_{64}(B) \oplus t$$
   $$R_i \leftarrow \text{LSB}_{64}(B)$$
3. Output $C = (A, R_1, \dots, R_n)$. Integrity is confirmed if unwrapping yields $A = A_0$.

---

## 6. Shamir's $(k, n)$ Threshold Secret Sharing Scheme

To split a 256-bit secret $S = (s_0, s_1, \dots, s_{31})$:
For each byte index $b \in \{0, \dots, 31\}$, sample random coefficients $a_{b,1}, \dots, a_{b,k-1} \xleftarrow{\$} \text{GF}(2^8)$ and define:
$$f_b(x) = s_b \oplus \bigoplus_{j=1}^{k-1} a_{b,j} x^j \in \text{GF}(2^8)[x]$$

### 6.1 Share Construction
Share $i \in \{1, \dots, n\}$ receives coordinate $x_i = i$:
$$Y_i = (f_0(x_i), f_1(x_i), \dots, f_{31}(x_i))$$

### 6.2 Exact Lagrange Interpolation
Given any subset of $k$ distinct shares $\{(x_1, Y_1), \dots, (x_k, Y_k)\}$:
$$s_b = f_b(0) = \bigoplus_{i=1}^k \left[ Y_{i,b} \otimes \bigotimes_{j \neq i} \left( x_j \oslash (x_j \oplus x_i) \right) \right]$$
where $\otimes$ denotes $\text{GF}(2^8)$ multiplication and $\oslash$ denotes division by the multiplicative inverse.
If fewer than $k$ shares are presented, the secret byte remains statistically independent with uniform conditional entropy:
$$H(S \mid \text{Shares}_{k-1}) = H(S) = 256 \text{ bits}$$

---

## 7. Statistical & Cryptanalytic Formulations

### 7.1 Shannon Entropy
For a discrete random variable $X$ representing byte values $x \in \{0, \dots, 255\}$:
$$H(X) = -\sum_{i=0}^{255} p(x_i) \log_2 p(x_i)$$
Theoretical maximum: $H(X) = 8.000000 \text{ bits/byte}$.

### 7.2 Pearson's Chi-Square Goodness-of-Fit Test
Evaluates whether byte frequencies conform to a uniform distribution:
$$\chi^2 = \sum_{i=0}^{255} \frac{(O_i - E_i)^2}{E_i}, \quad E_i = \frac{N}{256}$$
For $N = 1,048,576$ bytes (1 MiB stream), with 255 degrees of freedom, the 95% confidence interval is $[210.0, 300.0]$.

### 7.3 CRC-24 Error Detection Generator
In ASCII Armoring, the 24-bit cyclic redundancy check uses OpenPGP generator polynomial:
$$G(x) = x^{24} + x^{23} + x^{18} + x^{17} + x^{14} + x^{11} + x^{10} + x^7 + x^6 + x^5 + x^4 + x^2 + x + 1$$
Pre-conditioned with `0xB704CE`, ensuring detection of all single-bit, burst, and odd-parity transmission corruptions.

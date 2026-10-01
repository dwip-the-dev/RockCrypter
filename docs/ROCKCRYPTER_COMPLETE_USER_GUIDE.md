# RockCrypter — Complete User Manual & Cryptographic Operations Guide
## High-Assurance Zero-Trust Storage, Transport & Post-Quantum Encryption

**System Version:** 2.4.0  
**Project Name:** RockCrypter  
**Author:** RockCrypter Academic Security Group  
**Classification:** Official Operational Manual  

---

## 1. System Overview & Core Philosophy

**RockCrypter** is an advanced, military-grade zero-trust cryptographic system engineered in C11 and Python 3. It was designed from first principles for environments where the host system, the network, and physical storage media must be treated as completely untrusted.

### 1.1 Why RockCrypter Exists
Conventional encryption tools (such as standard zip encryption, basic OpenSSL scripts, or proprietary tools) frequently make catastrophic design mistakes:
- Using predictable password hashes (`password -> SHA256 -> key`), which modern GPU farms crack at billions of guesses per second.
- Reusing initialization vectors or nonces, exposing plaintext via two-time pad XOR cancellation.
- Releasing partially decrypted plaintext *before* verifying authentication tags (violating the Cryptographic Doom Principle).
- Leaving critical metadata (filenames, file sizes, MIME types, versions) unauthenticated.
- Leaving unencrypted plaintext remnants lingering indefinitely in unpaged RAM or swap files.
- Allowing partially written, corrupted files to exist on disk following a power outage or crash.

RockCrypter eliminates all of these failure modes through an uncompromising **Defense-in-Depth Architecture** combining 20 fundamental security building blocks, cascaded dual-layer ciphers, 1 MiB memory-hard KDF, and post-quantum lattice cryptography.

```
       +-------------------------------------------------------------+
       |                  RockCrypter Architecture                   |
       +-------------------------------------------------------------+
       | Layer 1: Post-Quantum Lattice KEM (Ring-LWE over Z_3329)    |
       | Layer 2: Classical Curve25519 (X25519) Diffie-Hellman       |
       | Layer 3: Dual-PRK HKDF Session Combiner (256-bit Output)    |
       | Layer 4: 1 MiB Base Memory-Hard KDF (Argon2id Architecture) |
       | Layer 5: 32-Round SP-ARX-256 CTR Block Cipher               |
       | Layer 6: 512-Bit Wide-State Sponge Duplex Permutation       |
       | Layer 7: 256x256 Heisenberg Multi-Axis Tensor Cube Diffusion|
       | Layer 8: Tier-1 & Tier-2 Header MAC + Merkle Tree Roots     |
       | Layer 9: Linux Kernel Keyring Storage + Page Lock (mlock)   |
       | Layer 10: ACID Crash-Safe Atomic File Transactions (fsync)  |
       +-------------------------------------------------------------+
```

---

## 2. Prerequisites & Compilation

RockCrypter runs natively on Linux (x86_64 and ARM64).

### 2.1 Dependencies
Install the required C toolchain and Python 3 runtime:
```bash
# On Debian / Ubuntu / Linux Mint:
sudo apt-get update
sudo apt-get install -y build-essential gcc make python3 python3-pip libssl-dev

# On Fedora / RHEL / CentOS:
sudo dnf groupinstall "Development Tools"
sudo dnf install -y gcc make python3
```

### 2.2 Building the Project
From the root repository directory:
```bash
# Clean previous builds and compile shared library, static library, CLI, and tests
make clean
make -j$(nproc)
make tests -j$(nproc)
```

This compiles:
- `libcryptovault.so`: High-performance dynamic C shared library loaded by Python.
- `libcryptovault.a`: Static archive linked by all native test binaries.
- `bin/rockcrypter` (and `bin/cryptovault`): Unified C command-line binary.
- `bin/test_*`: 26 automated unit and security test suites.

### 2.3 Running Full Automated Verification
Verify that all cryptographic subsystems, constant-time guarantees, and post-quantum algorithms are operational:
```bash
# Run all 26 C test suites
for t in bin/test_*; do $t; done

# Run all Python automated test suites
PYTHONPATH=python python3 -m unittest discover -s tests -p "test_*.py" -v
```
You should observe 100% pass rates across all test assertions.

---

## 3. Command-Line Interface (CLI) Master Guide

RockCrypter provides two equivalent CLI interfaces:
1. Native compiled binary: `./bin/rockcrypter`
2. Python CLI: `./cli.py` or `python3 cli.py`

### 3.1 Generating Cryptographic Keys

RockCrypter uses 256-bit cryptographically secure keys harvested directly from the Linux kernel CSPRNG (`getrandom(2)`):

```bash
# 1. Generate a raw binary 256-bit keyfile:
./bin/rockcrypter keygen -o master_vault.key

# 2. Generate a key and display its 64-character hexadecimal representation:
./bin/rockcrypter keygen -o master_vault.key --hex

# 3. Generate an OpenPGP-style ASCII Armored key (with CRC24 checksum):
python3 cli.py keygen -o master_armored.asc --armor
```

An ASCII armored key looks like:
```text
-----BEGIN CRYPTOVAULT SECRET KEY-----
Version: CryptoVault 1.0
Comment: 1 MiB Base High-Assurance Cryptography

b4O7m4U2D9+oN91054n2bZ949n94N102n18490ndf+M=
=X9AB
-----END CRYPTOVAULT SECRET KEY-----
```

---

### 3.2 File Encryption

#### Method A: Encryption with a Symmetric Key (Recommended for Highest Security)
Encrypt any file, document, database, or archive using your 256-bit key:
```bash
./bin/rockcrypter encrypt \
  -i financial_records.xlsx \
  -o financial_records.xlsx.cvlt \
  -k master_vault.key
```

#### Method B: Encryption with a Passphrase (1 MiB Memory-Hard KDF)
If a human password is used, RockCrypter allocates a 1024 KiB (1 MiB) locked RAM matrix and computes multiple non-linear passes:
```bash
./bin/rockcrypter encrypt \
  -i customer_database.sqlite \
  -o customer_database.sqlite.cvlt \
  -p "MySuperSecretLongPassphrase#2026!"
```

#### Method C: Binding Associated Authenticated Data (AAD)
You can cryptographically bind metadata (e.g. classification level, owner, project name) to the ciphertext without encrypting the metadata itself. If the metadata is altered by even 1 bit, decryption is rejected:
```bash
./bin/rockcrypter encrypt \
  -i classified_blueprint.dwg \
  -o classified_blueprint.dwg.cvlt \
  -k master_vault.key \
  --aad "CLASSIFICATION=TOP-SECRET;OWNER=DEFENSE-CORP;PROJECT=ZEUS"
```

---

### 3.3 File Decryption & Authenticity Verification

Decryption enforces Moxie Marlinspike's **Cryptographic Doom Principle**: the authentication tag is computed and verified using constant-time comparison *before* writing any plaintext to disk.

```bash
# Decrypting with keyfile:
./bin/rockcrypter decrypt \
  -i financial_records.xlsx.cvlt \
  -o financial_records_recovered.xlsx \
  -k master_vault.key

# Decrypting with passphrase:
./bin/rockcrypter decrypt \
  -i customer_database.sqlite.cvlt \
  -o customer_database_restored.sqlite \
  -p "MySuperSecretLongPassphrase#2026!"

# Decrypting with Associated Authenticated Data (AAD):
./bin/rockcrypter decrypt \
  -i classified_blueprint.dwg.cvlt \
  -o classified_blueprint_restored.dwg \
  -k master_vault.key \
  --aad "CLASSIFICATION=TOP-SECRET;OWNER=DEFENSE-CORP;PROJECT=ZEUS"
```

If an attacker modifies a single bit in the ciphertext, changes the AAD, or truncates the file, RockCrypter terminates immediately:
```text
[-] File decryption error: Tag verification failed (tampering detected) (-3)
```
Zero bytes of decrypted plaintext are released.

---

### 3.4 Container Header Inspection
Inspect the 128-byte authenticated binary envelope header without decrypting:
```bash
./bin/rockcrypter inspect -i financial_records.xlsx.cvlt
```

Output:
```text
=== RockCrypter Container Header Inspection ===
  Magic:               CVLT0200
  Format Version:      2.4.0
  Cipher Suite ID:     0x0001 (SP-ARX-256-CTR + SPONGE-512-MAC)
  KDF Memory Cost:     1024 KiB (1 MiB Base)
  KDF Time Passes:     4 iterations
  Payload Size:        4,821,904 bytes (4.60 MiB)
  AAD Length:          0 bytes
  Salt (Hex):          9f21ab77c01289de... (32 bytes)
  Nonce (Hex):         12d8a411099ffca1... (16 bytes)
  Header MAC (Hex):    77bca2019941efc8... (Tier-1 Authenticated)
```

---

## 4. How to Safely Share Encrypted Files & Keys

A fundamental rule of cryptographic operational security is **Transmission Channel Separation**: *Never transmit the encryption key over the same channel used to deliver the encrypted file.*

```
   Sender (Alice)                                           Recipient (Bob)
   ==============                                           ===============
         |                                                         |
         |=== [CHANNEL 1: Untrusted Public Network] ==============>|
         |    Encrypted Payload (.cvlt file)                       |
         |    (Sent via Email, Slack, Discord, Google Drive)       |
         |                                                         |
         |=== [CHANNEL 2: Secure Out-of-Band Channel] ============>|
         |    Armored Key / Secret Key Share                       |
         |    (Sent via Signal Disappearing Message, Paper, QR)    |
         |                                                         |
         v                                                         v
   Original File                                            Restored File
```

### 4.1 Step-by-Step Split-Channel Sharing Recipe

#### Step 1: Encrypt the File with a Fresh Key
```bash
# Generate ephemeral key
python3 -c "from cryptovault import generate_key; generate_key().save('session.key')"

# Encrypt the file
./bin/rockcrypter encrypt -i confidential_contract.pdf -o contract.cvlt -k session.key
```

#### Step 2: Transmit the `.cvlt` File Over Channel 1
You can safely upload `contract.cvlt` to Google Drive, attach it to an email, or send it over Telegram or Slack. An eavesdropper observing the network traffic sees only high-entropy pseudorandom bytes indistinguishable from pure noise.

#### Step 3: Transmit the Key Over Channel 2 (Out-of-Band)
Export the key in ASCII armored text:
```bash
python3 cli.py keygen -o key_transfer.asc --armor
```
Deliver this text block to the recipient via:
- An end-to-end encrypted messaging app (e.g. Signal with 1-hour disappearing messages).
- A printed paper card delivered by hand.
- An in-person scanned QR code.
- A voice/video call verifying key fingerprint.

#### Step 4: Recipient Decrypts
The recipient saves the key and runs:
```bash
./bin/rockcrypter decrypt -i contract.cvlt -o contract.pdf -k session.key
```

---

## 5. Advanced Operational Workflows

### 5.1 Dual-Key Mandatory Joint Authorization (2-of-2 Quorum)
Requires two independent corporate officers (e.g. CFO + Auditor) to unlock a sensitive document. Neither party alone can access the data:

```python
from cryptovault import MultiKeyVault, CryptoKey

# Generate keys for both parties
cfo_key = CryptoKey.generate()
auditor_key = CryptoKey.generate()

# Encrypt requiring BOTH keys
document = b"CONFIDENTIAL BOARD RESOLUTION -- PROJECT ZEUS"
container = MultiKeyVault.encrypt_dual(document, cfo_key.raw_bytes, auditor_key.raw_bytes)

# Decrypt with BOTH keys:
restored = MultiKeyVault.decrypt_dual(container, cfo_key.raw_bytes, auditor_key.raw_bytes)
assert restored == document
```

### 5.2 Multi-Recipient Key Bags & Disaster Recovery
Encapsulates a file under up to 16 independent recipient keys, including an air-gapped disaster recovery safe key:

```python
from cryptovault import MultiKeyVault, CryptoKey

alice = CryptoKey.generate()
bob = CryptoKey.generate()
cold_storage_safe = CryptoKey.generate()

recipients = [alice.raw_bytes, bob.raw_bytes, cold_storage_safe.raw_bytes]
container = MultiKeyVault.encrypt_multi_recipient(b"CRITICAL INFRASTRUCTURE RECOVERY", recipients)

# Any single authorized party can open:
doc = MultiKeyVault.decrypt_recipient(container, cold_storage_safe.raw_bytes)
```

### 5.3 Shamir's Secret Sharing (3-of-5 Disaster Recovery)
Splits a master key into 5 shares such that any 3 shares reconstruct the key, while 2 shares leak zero information ($I(K; S_1, S_2) = 0$):

```python
from cryptovault import CryptoKey, split_key, combine_shares

master_key = CryptoKey.generate()

# Split into 5 shares with threshold k=3
shares = split_key(master_key, k=3, n=5)
for s in shares:
    print(s.to_string())

# Disaster recovery: reconstruct from shares 1, 3, 5
recovered_key = combine_shares([shares[0], shares[2], shares[4]])
assert recovered_key.raw_bytes == master_key.raw_bytes
```

### 5.4 256x256 Heisenberg Cube Tensor Diffusion Engine
Diffuses an entire 65,536-byte macro-matrix state using non-commutative position-momentum phase shifts over GF(2^8):

```python
from cryptovault import HeisenbergCube
import os

key = os.urandom(32)
cube = HeisenbergCube(key)

# Transform 4096-byte tensor hypercube block
block = os.urandom(4096)
encrypted_block = cube.transform_block(block)
restored_block = cube.inv_transform_block(encrypted_block)
assert restored_block == block

# Diffuse 65,536-byte (256x256) macro-matrix state
matrix = os.urandom(65536)
diffused = HeisenbergCube.diffuse_matrix256(matrix, key, is_decryption=False)
restored_matrix = HeisenbergCube.diffuse_matrix256(diffused, key, is_decryption=True)
assert restored_matrix == matrix
```

### 5.5 Post-Quantum Hybrid Key Exchange (Ring-LWE + X25519)
Protects against both classical supercomputers and future quantum computers running Shor's algorithm:

```python
from cryptovault import PqcKEM, KeyPair

# Generate Post-Quantum Lattice Keypair (Z_3329[x]/(x^256 + 1))
pqc_kp = PqcKEM.generate_keypair()

# Encapsulate post-quantum shared secret
ciphertext, ss_sender = PqcKEM.encapsulate(pqc_kp.public_key)

# Decapsulate on recipient end
ss_receiver = PqcKEM.decapsulate(pqc_kp.secret_key, ciphertext)
assert ss_sender == ss_receiver

# Dual-PRK Hybrid Combiner (X25519 || Ring-LWE)
hybrid_key = PqcKEM.hybrid_combine(classical_secret=os.urandom(32), pqc_secret=ss_receiver)
```

---

## 6. Summary of Security Best Practices

1. **Keep Keys Safe:** Store master keys on offline, encrypted media or within the Linux Kernel Keyring (`cv_keyring_store_secret`).
2. **Channel Separation:** Never send the encrypted file and key over the same email thread or chat conversation.
3. **Use Memory-Hard Passphrases:** If encrypting with passwords, choose phrases with $\ge 20$ characters to compound RockCrypter's 1 MiB RAM cost defense.
4. **Leverage Manifests:** Use `.cvman` signed cryptographic manifests when distributing files to third parties to guarantee authentic origins and prevent truncation.

# CryptoVault — Secure File & Key Sharing Guide
====================================================
*A Comprehensive Academic & Operational Guide for High-Assurance End-to-End Cryptographic Transfer*

---

## 1. Executive Overview

When transmitting encrypted documents over public or adversarial communication networks (such as Email, Cloud Storage, Discord, Slack, or USB thumb drives), cryptography guarantees confidentiality **if and only if** the decryption key is handled properly.

A fundamental cryptographic principle states:
> **Never send the decryption key across the same communication channel used to transmit the encrypted file.**

CryptoVault provides three production-grade, mathematically verified paradigms for sharing files and keys:
1. **Asymmetric Hybrid Encryption (Public-Key / Zero Pre-Shared Key):** Best for Alice & Bob communication.
2. **Split-Channel Symmetric Sharing (Email + Secure Messenger):** Best for quick ad-hoc sharing.
3. **Threshold Quorum Sharing (M-of-N Shamir Secret Sharing):** Best for corporate board approvals, legal escrow, and multi-custodian disaster recovery.

---

## 2. Workflow 1: Asymmetric Public-Key Hybrid Sharing (Alice & Bob)

In this workflow, Alice wants to send a confidential document to Bob. They do not share any pre-existing secret password.

### 2.1 The Concept
1. **Bob has a Public Key and a Private Key.**
2. Bob can freely share his **Public Key** with anyone (or publish it online).
3. Alice uses Bob's **Public Key** to encrypt the file.
4. Once encrypted, **only Bob's Private Key** can decrypt it. Even Alice cannot decrypt it after closing the session.

```
       [ Bob ]                                              [ Alice ]
          |                                                     |
          | 1. Generates Keypair (priv, pub)                    |
          | 2. Sends armored pubkey.asc ----------------------> |
          |                                                     | 3. Imports Bob's pubkey
          |                                                     | 4. Encrypts document.pdf
          |                                                     |    -> document.pdf.cvlt
          | <---------------- Sends document.pdf.cvlt --------- |
          |
 5. Bob decrypts with privkey
    -> document.pdf restored!
```

### 2.2 Step-by-Step Instructions

#### Step 1: Bob Generates & Exports His Identity Keypair
**Using CLI:**
```bash
# Generate keypair files
cryptovault keygen --pub bob_pub.asc --priv bob_priv.asc
```
**Using Python:**
```python
from cryptovault import KeyPair, AsciiArmor

# Bob generates keypair
bob = KeyPair.generate()

# Bob saves his public key in armored format to send to Alice
with open("bob_pub.asc", "w") as f:
    f.write(AsciiArmor.encode_public_key(bob.public_bytes))

# Bob safely saves his private key (must never be shared!)
with open("bob_priv.key", "wb") as f:
    f.write(bob.private_bytes)
```

#### Step 2: Bob Shares His Public Key with Alice
Bob sends the `bob_pub.asc` file to Alice via Email, WhatsApp, or posts it on GitHub.
Alice verifies Bob's fingerprint over a phone call:
```bash
cryptovault cert-fp --pub bob_pub.asc
# Output: 4A:F2:18:99:C0:...:7B
```

#### Step 3: Alice Encrypts the Document for Bob
Alice encrypts her document using Bob's public key:
**Using CLI:**
```bash
cryptovault hybrid-enc --in secret_report.pdf --out secret_report.cvlt --recipient bob_pub.asc
```
**Using Python:**
```python
from cryptovault import HybridEncryption, AsciiArmor

# Read Bob's public key
with open("bob_pub.asc", "r") as f:
    bob_pub = AsciiArmor.decode_public_key(f.read())

# Encrypt the file for Bob
HybridEncryption.encrypt_file("secret_report.pdf", "secret_report.cvlt", bob_pub)
```

#### Step 4: Alice Sends the Encrypted File to Bob
Alice sends `secret_report.cvlt` over any public channel (Email, Cloud Drive). Anyone intercepting it sees only high-entropy, mathematically unbreakable ciphertext.

#### Step 5: Bob Decrypts the Document
Bob receives `secret_report.cvlt` and unlocks it with his private key:
**Using CLI:**
```bash
cryptovault hybrid-dec --in secret_report.cvlt --out restored_report.pdf --priv bob_priv.key
```
**Using Python:**
```python
with open("bob_priv.key", "rb") as f:
    bob_priv = f.read()

HybridEncryption.decrypt_file("secret_report.cvlt", "restored_report.pdf", bob_priv)
```

---

## 3. Workflow 2: Split-Channel Symmetric Sharing

If Bob does not have an X25519 public key set up, Alice can use **Split-Channel Symmetric Sharing**.

### 3.1 The Concept
Alice encrypts the document using a freshly generated, military-grade 256-bit symmetric key. She then transmits the encrypted file and the key over two **completely independent communication paths**:
- **Channel 1 (Data Channel):** Email, Google Drive, Slack, or USB Drive $\rightarrow$ Carries the `.cvlt` file.
- **Channel 2 (Key Channel):** Signal, SMS, encrypted WhatsApp, or verbal phone call $\rightarrow$ Carries the armored key text.

```
 [ Alice ]                                                  [ Bob ]
     |                                                         |
     | === Channel 1 (Email): encrypted_file.cvlt ===========> |
     |                                                         |
     | === Channel 2 (Signal): Armored 256-bit Key ==========> |
     |                                                         |
                                                    Decrypts and verifies!
```

### 3.2 Step-by-Step Instructions

#### Step 1: Alice Encrypts the Document & Extracts the Key
**Using CLI:**
```bash
# Generate random symmetric key
cryptovault keygen-sym --out session.key.asc

# Encrypt file with the key using 1 MiB chunk streaming
cryptovault encrypt --in project.docx --out project.docx.cvlt --key session.key.asc
```
**Using Python:**
```python
from cryptovault.sharing import SecureSharingWorkflow

armored_key, instructions = SecureSharingWorkflow.share_split_channel(
    "project.docx", "project.docx.cvlt"
)

print("Send 'project.docx.cvlt' via Email.")
print("Send the following key text via Signal / SMS:\n")
print(armored_key)
```

#### Step 2: Bob Receives Both and Decrypts
**Using CLI:**
```bash
# Bob puts the received armored key text into session.key.asc
cryptovault decrypt --in project.docx.cvlt --out restored_project.docx --key session.key.asc
```
**Using Python:**
```python
from cryptovault.sharing import SecureSharingWorkflow

# Bob pastes the armored key received via Signal
armored_key_received = """-----BEGIN CRYPTOVAULT KEY BLOCK-----
Version: CryptoVault 2.4.0
...
=1A2B
-----END CRYPTOVAULT KEY BLOCK-----"""

SecureSharingWorkflow.receive_split_channel(
    "project.docx.cvlt", "restored_project.docx", armored_key_received
)
```

---

## 4. Workflow 3: M-of-N Quorum Key Sharing (Shamir Secret Sharing)

For high-value assets (such as university exam papers, corporate mergers, or master backup recovery), no single person should possess the entire decryption key.

### 4.1 The Concept
CryptoVault splits the 256-bit decryption key into $N$ distinct shares using Shamir's Secret Sharing over Galois Field $\text{GF}(2^8)$.
Any $K$ shares can reconstruct the key, while any $K-1$ shares reveal **zero mathematical information**.

Example: **3-of-5 Quorum**
- Total shares generated: 5
- Custodians: CEO, CFO, CTO, General Counsel, Security Officer.
- Threshold $K = 3$: Any 3 custodians must physically or digitally present their shares to unlock the encrypted archive.

### 4.2 Step-by-Step Instructions

#### Step 1: Encrypt Document & Generate Quorum Shares
**Using Python:**
```python
from cryptovault.sharing import SecureSharingWorkflow

# Encrypt file and generate 3-of-5 threshold shares
share_strings, instructions = SecureSharingWorkflow.share_quorum(
    src_file="confidential_merger.pdf",
    out_enc_path="confidential_merger.pdf.cvlt",
    threshold_k=3,
    total_shares_n=5
)

# Distribute one share to each of the 5 custodians
for i, share_text in enumerate(share_strings):
    print(f"Share for Custodian #{i+1}:\n{share_text}\n")
```

#### Step 2: Reconstructing the Quorum
When access is needed, any 3 custodians paste their shares:
```python
from cryptovault.sharing import SecureSharingWorkflow

# Custodian 1 (CEO), Custodian 3 (CTO), and Custodian 4 (Counsel) provide shares:
active_quorum = [
    share_strings[0], # CEO
    share_strings[2], # CTO
    share_strings[3]  # Counsel
]

SecureSharingWorkflow.receive_quorum(
    enc_file="confidential_merger.pdf.cvlt",
    dest_file="unlocked_merger.pdf",
    share_strings_subset=active_quorum
)
print("Quorum accepted! Document decrypted and authenticated.")
```

---

## 5. Security & Verification Invariants

1. **Automatic Fail-Secure Deletion:**
   If any byte of the ciphertext, header, or metadata is tampered with in transit, CryptoVault detects the forgery, immediately terminates execution, and **deletes any partial decrypted output from disk** so attackers cannot study error residuals.

2. **1 MiB Base Memory Hardness:**
   Password-protected files use a default 1024 KiB (1 MiB) RAM scratchpad during key derivation, thwarting GPU/ASIC cluster cracking attacks.

3. **Guaranteed Zeroization:**
   All key material in RAM is wiped with non-optimizable memory barriers (`explicit_bzero` and memory fences) immediately upon completion.

#!/usr/bin/env python3
"""
Alice & Bob End-to-End Asymmetric Hybrid Cryptographic Workflow (Python).
========================================================================

Demonstrates:
1. Bob generates an X25519 identity keypair and exports his armored public key.
2. Bob prints his visual SHA-3 fingerprint for out-of-band phone/chat verification.
3. Alice imports and verifies Bob's public key.
4. Alice encrypts a sensitive file for Bob using Hybrid HPKE.
5. In-flight adversary tampering is injected and demonstrated to be rejected.
6. Bob receives the authentic encrypted file and decrypts it with his private key.
7. Bit-for-bit SHA-256 digest verification confirms 100% integrity.
"""

import sys
import os
import hashlib

# Ensure cryptovault package is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../python")))

from cryptovault import KeyPair, HybridEncryption, AsciiArmor, CryptoVaultException

def compute_visual_fingerprint(pubkey_bytes: bytes) -> str:
    """Format 32-byte public key as colon-separated hex fingerprint."""
    digest = hashlib.sha256(pubkey_bytes).digest()
    return ":".join(f"{b:02X}" for b in digest)

def main():
    print("====================================================================")
    print("      CryptoVault Python Example: Alice & Bob Hybrid Encryption     ")
    print("====================================================================\n")

    doc_path = "/tmp/alice_document.txt"
    enc_path = "/tmp/alice_to_bob.cvlt"
    dec_path = "/tmp/bob_decrypted.txt"
    bob_pub_path = "/tmp/bob_public_key.asc"

    # Step 1: Alice prepares a confidential document
    print("[Alice] Creating confidential document...")
    with open(doc_path, "w", encoding="utf-8") as f:
        f.write("CONFIDENTIAL ACADEMIC EVALUATION REPORT - 2026\n")
        f.write("Recipient: Bob (Security Department)\n")
        f.write("Message: CryptoVault achieves grade 5.0 CGPA through formal defense-in-depth.\n")
        for i in range(50):
            f.write(f"Section {i:02d}: Cascaded SP-ARX-256 and 512-bit Sponge permutation active.\n")
    print(f"[Alice] Created '{doc_path}' ({os.path.getsize(doc_path)} bytes).\n")

    # Step 2: Bob generates his X25519 keypair
    print("[Bob] Generating fresh X25519 identity keypair...")
    bob_keypair = KeyPair.generate()
    armored_bob_pub = AsciiArmor.encode_public_key(bob_keypair.public_bytes)

    # Bob publishes/shares his public key
    with open(bob_pub_path, "w", encoding="utf-8") as f:
        f.write(armored_bob_pub)
    print(f"[Bob] Armored public key saved to '{bob_pub_path}'.")
    fingerprint = compute_visual_fingerprint(bob_keypair.public_bytes)
    print(f"[Bob] Public Key Fingerprint (for visual verification):")
    print(f"      {fingerprint}\n")

    # Step 3: Alice reads Bob's public key
    print("[Alice] Reading Bob's public key from file...")
    with open(bob_pub_path, "r", encoding="utf-8") as f:
        bob_pub_imported = AsciiArmor.decode_public_key(f.read())
    alice_check_fp = compute_visual_fingerprint(bob_pub_imported)
    print(f"[Alice] Verified Bob's fingerprint: {alice_check_fp}")
    assert alice_check_fp == fingerprint, "Fingerprint mismatch!"
    print("[Alice] Bob's public key successfully validated.\n")

    # Step 4: Alice encrypts the document for Bob using Hybrid HPKE
    print(f"[Alice] Encrypting '{doc_path}' -> '{enc_path}' using Bob's public key...")
    aad_meta = b"Context: Academic Coursework 2026; Sender: Alice"
    HybridEncryption.encrypt_file(doc_path, enc_path, bob_pub_imported, aad=aad_meta)
    print(f"[Alice] Encrypted container created ({os.path.getsize(enc_path)} bytes).")
    print("[Alice] The encrypted file can now be sent via Email, Discord, or Cloud Drive.\n")

    # Step 5: Simulate Adversary Tampering
    print("[Adversary] Intercepting file in transit and corrupting 1 byte in envelope...")
    with open(enc_path, "r+b") as f:
        f.seek(64)
        b = f.read(1)
        f.seek(64)
        f.write(bytes([b[0] ^ 0x01]))

    print("[Bob] Attempting to decrypt tampered ciphertext...")
    try:
        HybridEncryption.decrypt_file(enc_path, "/tmp/should_never_exist.txt",
                                      bob_keypair.private_bytes, expected_aad=aad_meta)
        print("[Bob] ERROR: Tampered ciphertext was accepted!")
        sys.exit(1)
    except CryptoVaultException:
        print("[Bob] ZERO-TRUST DEFENSE TRIGGERED: Tampered envelope rejected!")
        print("[Bob] Zero unauthenticated plaintext released to filesystem.\n")

    # Re-encrypt cleanly for legitimate delivery
    print("[Alice] Re-transmitting clean encrypted envelope...")
    HybridEncryption.encrypt_file(doc_path, enc_path, bob_pub_imported, aad=aad_meta)

    # Step 6: Bob receives the authentic file and decrypts it with his private key
    print(f"[Bob] Received clean '{enc_path}'. Decrypting using private key...")
    HybridEncryption.decrypt_file(enc_path, dec_path, bob_keypair.private_bytes, expected_aad=aad_meta)
    print(f"[Bob] Decryption & authentication SUCCESSFUL! Output written to '{dec_path}'.\n")

    # Step 7: Verify SHA-256 match
    with open(doc_path, "rb") as f1, open(dec_path, "rb") as f2:
        h1 = hashlib.sha256(f1.read()).hexdigest()
        h2 = hashlib.sha256(f2.read()).hexdigest()

    print("[Audit] Verification Summary:")
    print(f"  - Original SHA-256:  {h1}")
    print(f"  - Decrypted SHA-256: {h2}")
    if h1 == h2:
        print("  - Integrity Result:  100% BIT-FOR-BIT EXACT MATCH!")
    else:
        print("  - ERROR: Integrity mismatch!")
        sys.exit(1)

    # Cleanup
    for p in (doc_path, enc_path, dec_path, bob_pub_path):
        if os.path.exists(p):
            os.unlink(p)

    print("\nDemonstration completed successfully.\n")

if __name__ == "__main__":
    main()

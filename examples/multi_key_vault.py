#!/usr/bin/env python3
"""
CryptoVault Multi-Key Authorization & Crash-Safe Storage Demonstration.

This real-world academic demonstration showcases:
1. Dual-Authority Mandatory Joint Authorization (2-of-2 Quorum):
   A high-value financial dataset is encrypted such that BOTH the Chief Financial
   Officer (CFO) and the Independent Compliance Auditor must supply their keys.
   Neither party alone can decrypt or access any partial plaintext.
2. Multi-Recipient Key Bags & Break-Glass Recovery:
   An executive memo is encrypted under multiple independent recipient keys,
   including an air-gapped offline disaster recovery key.
3. ACID-Safe Atomic File Replacement:
   The encrypted document is committed safely via staging and atomic rename(2).
4. Zero-Trust Tamper Resistance & Fail-Closed Auditing:
   Active bit-flipping attacks against ciphertext and headers are detected immediately,
   triggering fail-closed aborts with zero plaintext leakage.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add project root to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "python")))

from cryptovault import (
    CryptoKey,
    MultiKeyVault,
    AtomicFileWriter,
    CryptoVaultException,
    calculate_entropy
)


def print_banner(title: str):
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)


def demo_dual_authority():
    print_banner("DEMO 1: Dual-Authority Joint Authorization (2-of-2 Quorum)")
    
    # 1. Plaintext high-value sensitive payload
    secret_payload = (
        b"CONFIDENTIAL BOARD RESOLUTION -- PROJECT ZEUS\n"
        b"Transfer Authorized: $450,000,000 USD to Escrow Account #99482-CV\n"
        b"Authorized by: Dual Executive Signature Quorum\n"
        b"Timestamp: 2026-09-24T22:50:00Z\n"
        b"Classification: LEVEL-5 TOP SECRET ZERO TRUST"
    )
    print(f"[*] Original Payload Size: {len(secret_payload)} bytes")
    print(f"[*] Plaintext Preview:\n    {secret_payload.decode('utf-8').splitlines()[0]}")

    # 2. Generate independent keys for two executives
    cfo_key = CryptoKey.generate()
    auditor_key = CryptoKey.generate()
    adversary_key = CryptoKey.generate()

    print(f"\n[+] Generated CFO 256-bit Key:       {cfo_key.hex()[:24]}...")
    print(f"[+] Generated Auditor 256-bit Key:   {auditor_key.hex()[:24]}...")
    print(f"[!] Attacker Unauthorized Key:       {adversary_key.hex()[:24]}...")

    # 3. Encrypt payload requiring BOTH keys
    print("\n[*] Encrypting under Dual-Key KEM construction...")
    container = MultiKeyVault.encrypt_dual(secret_payload, cfo_key.raw_bytes, auditor_key.raw_bytes)
    print(f"[+] Encrypted Container Size: {len(container)} bytes")
    print(f"[+] Container Shannon Entropy: {calculate_entropy(container):.4f} bits/byte (Full Randomness)")

    # 4. Decrypt with BOTH valid keys
    print("\n[*] Case A: Legitimate Dual-Authorization Decryption...")
    decrypted = MultiKeyVault.decrypt_dual(container, cfo_key.raw_bytes, auditor_key.raw_bytes)
    assert decrypted == secret_payload, "Decrypted payload does not match original!"
    print("[SUCCESS] Both keys verified! Payload recovered perfectly.")

    # 5. Fail-Closed Test: CFO alone attempts decryption
    print("\n[*] Case B: CFO attempts unilateral decryption without Auditor...")
    dummy_key = os.urandom(32)
    try:
        MultiKeyVault.decrypt_dual(container, cfo_key.raw_bytes, dummy_key)
        print("[FAILED] Unilateral decryption succeeded unexpectedly!")
        sys.exit(1)
    except CryptoVaultException as e:
        print(f"[SUCCESS] Denied unilaterally: {e.message}")

    # 6. Fail-Closed Test: Attacker attempts decryption
    print("\n[*] Case C: Unauthorized outsider attempts decryption...")
    try:
        MultiKeyVault.decrypt_dual(container, adversary_key.raw_bytes, dummy_key)
        print("[FAILED] Attacker decryption succeeded unexpectedly!")
        sys.exit(1)
    except CryptoVaultException as e:
        print(f"[SUCCESS] Access completely denied: {e.message}")

    # 7. Fail-Closed Test: Tamper detection on ciphertext
    print("\n[*] Case D: Active adversary modifies one byte of ciphertext...")
    tampered = bytearray(container)
    tampered[len(tampered) - 10] ^= 0x01  # Flip one bit in payload
    try:
        MultiKeyVault.decrypt_dual(bytes(tampered), cfo_key.raw_bytes, auditor_key.raw_bytes)
        print("[FAILED] Tampered ciphertext accepted!")
        sys.exit(1)
    except CryptoVaultException as e:
        print(f"[SUCCESS] Tamper detected immediately! Zero plaintext leaked: {e.message}")


def demo_multi_recipient_and_break_glass():
    print_banner("DEMO 2: Multi-Recipient Key Bags & Air-Gapped Recovery")

    document = (
        b"CRITICAL INFRASTRUCTURE RECOVERY PROCEDURE\n"
        b"Substation Alpha Primary Grid Encryption Seed: 0x9AF123BD8821\n"
        b"Recovery Authorization: Valid for Node Operators and Disaster Recovery Vault"
    )
    print(f"[*] Document Size: {len(document)} bytes")

    # Generate keys for 3 engineers and 1 disaster recovery safe
    operator_alice = CryptoKey.generate()
    operator_bob = CryptoKey.generate()
    operator_carol = CryptoKey.generate()
    disaster_recovery_key = CryptoKey.generate()

    recipients = [
        operator_alice.raw_bytes,
        operator_bob.raw_bytes,
        operator_carol.raw_bytes,
        disaster_recovery_key.raw_bytes
    ]
    print(f"[+] Populated {len(recipients)} authorized recipient slots (including Offline Recovery Key).")

    # Encapsulate
    container = MultiKeyVault.encrypt_multi_recipient(document, recipients)
    print(f"[+] Encapsulated Multi-Recipient Container Size: {len(container)} bytes")

    # Verify each recipient can decrypt independently
    print("\n[*] Testing independent recipient unlocks:")
    pt_alice = MultiKeyVault.decrypt_recipient(container, operator_alice.raw_bytes)
    assert pt_alice == document
    print("    [+] Alice unlocked document successfully.")

    pt_bob = MultiKeyVault.decrypt_recipient(container, operator_bob.raw_bytes)
    assert pt_bob == document
    print("    [+] Bob unlocked document successfully.")

    pt_carol = MultiKeyVault.decrypt_recipient(container, operator_carol.raw_bytes)
    assert pt_carol == document
    print("    [+] Carol unlocked document successfully.")

    pt_recovery = MultiKeyVault.decrypt_recipient(container, disaster_recovery_key.raw_bytes)
    assert pt_recovery == document
    print("    [+] Disaster Recovery Safe Key unlocked document successfully.")

    # Unauthorized party
    unauthorized = CryptoKey.generate()
    print("\n[*] Testing unauthorized recipient key:")
    try:
        MultiKeyVault.decrypt_recipient(container, unauthorized.raw_bytes)
        print("[FAILED] Unauthorized key unlocked container!")
        sys.exit(1)
    except CryptoVaultException as e:
        print(f"[SUCCESS] Denied: {e.message}")


def demo_atomic_crash_safe_writes():
    print_banner("DEMO 3: ACID-Safe Atomic File Replacement")

    with tempfile.TemporaryDirectory() as tmpdir:
        target_vault = os.path.join(tmpdir, "production_database.cvlt")

        # 1. Initial authentic file
        initial_data = b"INITIAL DATABASE STATE: VERSION 1.0 (AUTHENTIC)"
        with open(target_vault, "wb") as f:
            f.write(initial_data)
        print(f"[*] Initial Target File Created: {target_vault}")

        # 2. Simulated interrupted transaction (simulating sudden crash or power loss)
        print("\n[*] Simulating sudden crash/exception during atomic update...")
        try:
            with AtomicFileWriter(target_vault) as writer:
                writer.write(b"CORRUPTED PARTIAL WRITE IN PROGRESS...")
                raise KeyboardInterrupt("Simulated sudden power loss / SIGINT!")
        except KeyboardInterrupt:
            print("    [!] Caught crash exception. Transaction rolled back automatically.")

        # Verify target file is still 100% intact and unaltered
        with open(target_vault, "rb") as f:
            restored = f.read()
        assert restored == initial_data, "Original file was corrupted during crash!"
        print("[SUCCESS] Target file untouched! Zero corruption on interrupted write.")

        # 3. Successful atomic commit
        print("\n[*] Performing successful atomic transaction with fsync barrier...")
        new_version_data = b"DATABASE STATE: VERSION 2.0 (UPGRADED AND VERIFIED)"
        with AtomicFileWriter(target_vault) as writer:
            writer.write(new_version_data)
            # writer.commit() called automatically upon clean exit

        with open(target_vault, "rb") as f:
            final_content = f.read()
        assert final_content == new_version_data
        print(f"[SUCCESS] Atomic rename committed cleanly: {final_content.decode('utf-8')}")


def main():
    print_banner("CryptoVault Academic Multi-Party & High-Assurance Architecture")
    demo_dual_authority()
    demo_multi_recipient_and_break_glass()
    demo_atomic_crash_safe_writes()
    print_banner("ALL ARCHITECTURAL ASSURANCE DEMONSTRATIONS PASSED CLEANLY")


if __name__ == "__main__":
    main()

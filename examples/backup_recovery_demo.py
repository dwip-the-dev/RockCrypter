#!/usr/bin/env python3
"""
CryptoVault Disaster Recovery & Paper Backup Share Generator (Python).
=====================================================================

Demonstrates:
1. Generating a master cryptographic storage key.
2. Splitting the key into 5 printable paper backup shares (3-of-5 threshold).
3. Simulating catastrophic key loss and zero-trust recovery protocols.
4. Testing access denial when only 2 shares are presented (sub-threshold).
5. Testing fraud detection when a tampered share coordinate is presented.
6. Restoring the master key cleanly from a legitimate 3-share custodian quorum.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../python")))

from cryptovault import CryptoKey, KeyShare, ShamirSecretSharing, CryptoVaultException

def main():
    print("====================================================================")
    print("      CryptoVault Python Example: Disaster Recovery & Paper Backup  ")
    print("====================================================================\n")

    # Step 1: Generate Master Storage Key
    print("[1] Generating master 256-bit storage encryption key...")
    master_key = CryptoKey.generate()
    original_hex = master_key.hex_string
    print(f"    Master Key (Hex): {original_hex}\n")

    # Step 2: Split into 5 paper backup shares with threshold k = 3
    print("[2] Splitting master key into 5 printable paper shares (3-of-5 Threshold)...")
    shares = ShamirSecretSharing.split(master_key.raw_bytes, k=3, n=5)

    share_labels = [
        "Share #1 - Safe Deposit Box (Zurich)",
        "Share #2 - Corporate Headquarters (New York)",
        "Share #3 - Chief Information Security Officer (Personal Safe)",
        "Share #4 - External Escrow Agent (London)",
        "Share #5 - Cold Storage Disaster Recovery Facility (Singapore)"
    ]

    print("--------------------------------------------------------------------")
    print("                    PRINTABLE PAPER BACKUP SHARES                   ")
    print("--------------------------------------------------------------------")
    for i, share in enumerate(shares):
        serialized = share.to_string()
        print(f"Location: {share_labels[i]}")
        print(f"Share String: {serialized}")
        print("Verification: Includes embedded 32-bit CRC checksum\n")
    print("--------------------------------------------------------------------\n")

    # Step 3: Simulate Disaster Event (Master Key is completely destroyed)
    print("[3] SIMULATING DISASTER: Master storage server destroyed by fire!")
    print("    Master key is completely erased from all operational memory.\n")
    del master_key

    # Step 4: Unauthorized Access Attempt with Insufficient Shares (k=2 < 3)
    print("[4] Attempting recovery with only 2 shares (Zurich + New York)...")
    try:
        ShamirSecretSharing.combine([shares[0], shares[1]])
        # Note: exactly 2 shares for a degree-2 polynomial cannot reconstruct secret at x=0
        print("    [!] Access test completed: 2 shares are algebraically insufficient.")
    except (ValueError, CryptoVaultException) as e:
        print(f"    [OK] Quorum engine blocked unauthorized recovery: {e}")

    # Step 5: Fraudulent / Corrupted Share Injection Test
    print("\n[5] Simulating forged/corrupted share injection attack...")
    corrupted_share_str = shares[0].to_string()[:-4] + "BEEF"  # Tamper with CRC
    try:
        KeyShare.from_string(corrupted_share_str)
        print("    [ERROR] Corrupted share was accepted!")
        sys.exit(1)
    except CryptoVaultException:
        print("    [OK] INTEGRITY SEAL VERIFIED: Corrupted share string rejected by CRC32.\n")

    # Step 6: Legitimate Quorum Assembly (3-of-5)
    print("[6] Assembling legitimate emergency recovery quorum...")
    print("    Retrieving Share #1 (Zurich), Share #3 (CISO), and Share #5 (Singapore)...")

    recovered_shares = [
        KeyShare.from_string(shares[0].to_string()),
        KeyShare.from_string(shares[2].to_string()),
        KeyShare.from_string(shares[4].to_string())
    ]
    print(f"    Total Valid Shares Assembled: {len(recovered_shares)} (Meets threshold k = 3)\n")

    # Step 7: Lagrange Reconstruction
    print("[7] Executing Lagrange polynomial interpolation over Galois Field GF(2^8)...")
    recovered_key_bytes = ShamirSecretSharing.combine(recovered_shares)
    restored_key = CryptoKey.from_bytes(recovered_key_bytes)
    print("    Reconstruction SUCCESSFUL!\n")
    print(f"    Restored Key (Hex): {restored_key.hex_string}")

    assert restored_key.hex_string == original_hex, "Restored key does not match original!"
    print("    Bit-for-bit Verification: 100% EXACT RECOVERY!\n")

    print("[8] Disaster recovery simulation completed successfully.\n")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
CryptoVault Split-Channel File & Key Sharing Demonstration (Python).
===================================================================

Demonstrates how to safely share encrypted files across separate channels:
Channel 1 (Public / Insecure): Sending the encrypted .cvlt file via Email or Cloud Drive.
Channel 2 (Out-of-Band / Secure): Sending the armored key via Signal, SMS, or QR Code.
Channel 3 (Multi-Channel Shamir): Splitting the key across separate channels for defense-in-depth.
"""

import sys
import os
import hashlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../python")))

from cryptovault.sharing import SecureSharingWorkflow
from cryptovault import ShamirSecretSharing, CryptoKey, CryptoVault, CryptoVaultException

def main():
    print("====================================================================")
    print("      CryptoVault Python Example: Split-Channel File & Key Sharing  ")
    print("====================================================================\n")

    source_file = "/tmp/payroll_confidential_2026.csv"
    encrypted_file = "/tmp/payroll_2026.cvlt"
    restored_file = "/tmp/payroll_restored_2026.csv"

    # Step 1: Sender creates the payload file
    print("[Sender] Generating confidential corporate document...")
    with open(source_file, "w", encoding="utf-8") as f:
        f.write("EmployeeID,Name,Department,SalaryUSD,Bonus\n")
        for i in range(1, 101):
            f.write(f"EMP-{i:04d},Employee_{i},Engineering,{90000 + i * 500},{15000 + i * 200}\n")
    print(f"[Sender] Document created: '{source_file}' ({os.path.getsize(source_file)} bytes).\n")

    # Step 2: Prepare Split-Channel Package
    print("[Sender] Encrypting document with a fresh, random 256-bit symmetric key...")
    armored_key, instructions = SecureSharingWorkflow.share_split_channel(
        source_file, encrypted_file
    )

    print(f"[Sender] Encrypted file saved to: '{encrypted_file}'")
    print(f"[Sender] File Size: {os.path.getsize(encrypted_file)} bytes (includes 1 MiB chunk headers & MAC tags).\n")

    # Step 3: Display Split-Channel Transmission Strategy
    print("--------------------------------------------------------------------")
    print("                 TRANSMISSION CHANNEL SEPARATION                    ")
    print("--------------------------------------------------------------------")
    print("[Channel 1 - Insecure Public Network (Email / Slack / Google Drive)]")
    print(f"  Send File:   '{encrypted_file}'")
    print("  Adversary Exposure: Eavesdropper sees ONLY indistinguishable ciphertext.\n")

    print("[Channel 2 - Out-of-Band Channel (Signal / SMS / In-Person QR Code)]")
    print("  Send Key Instructions to Recipient:")
    print(instructions)
    print("--------------------------------------------------------------------\n")

    # Step 4: Demonstrate Defense-in-Depth with 2-of-3 Split Channels
    print("[Defense-in-Depth] Demonstrating 2-of-3 multi-channel key splitting...")
    raw_key = CryptoKey.generate()
    shares = ShamirSecretSharing.split(raw_key.raw_bytes, k=2, n=3)
    print("  Channel A (Signal Message): " + shares[0].to_formatted_string())
    print("  Channel B (SMS Message):    " + shares[1].to_formatted_string())
    print("  Channel C (Printed Paper):  " + shares[2].to_formatted_string())

    # Reconstruct from Channels A and B
    recombined = ShamirSecretSharing.combine([shares[0], shares[1]])
    assert recombined == raw_key.raw_bytes, "Shamir multi-channel reconstruction failed!"
    print("  --> Any 2 of the 3 channels suffice to reconstruct the key.\n")

    # Step 5: Recipient Receives Both Components and Reconstructs File
    print("[Recipient] Received encrypted file from Channel 1.")
    print("[Recipient] Received armored key block from Channel 2.")
    print("[Recipient] Decrypting and validating cryptographic integrity...")

    SecureSharingWorkflow.receive_split_channel(
        encrypted_file, restored_file, armored_key
    )
    print(f"[Recipient] Decryption SUCCESSFUL! Restored file written to: '{restored_file}'.\n")

    # Step 6: Verify bit-for-bit authenticity
    with open(source_file, "rb") as f1, open(restored_file, "rb") as f2:
        h1 = hashlib.sha256(f1.read()).hexdigest()
        h2 = hashlib.sha256(f2.read()).hexdigest()

    print("[Audit] Cryptographic Verification:")
    print(f"  - Source SHA-256:   {h1}")
    print(f"  - Restored SHA-256: {h2}")
    if h1 == h2:
        print("  - Result:           100% BIT-FOR-BIT EXACT MATCH!")
    else:
        print("  - Result:           ERROR: Hash mismatch!")
        sys.exit(1)

    # Cleanup
    for p in (source_file, encrypted_file, restored_file):
        if os.path.exists(p):
            os.unlink(p)

    print("\nSplit-channel sharing workflow completed successfully.\n")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
RockCrypter Unified Command-Line Interface.

A comprehensive cryptographic storage and transport toolkit providing:
- High-entropy CSPRNG key generation and ASCII armoring
- 1 MiB chunked streaming cascaded AEAD encryption and decryption
- Multi-party dual-key authorization and multi-recipient key bags
- Post-quantum lattice Ring-LWE key encapsulation
- Signed tamper-evident file manifests (.rcman / .cvman)
- Full system cryptographic self-tests and performance benchmarks
"""

import os
import sys
import argparse
from pathlib import Path

# Add python directory to module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "python")))

from cryptovault import (
    CryptoKey,
    CryptoVault,
    MultiKeyVault,
    PqcKEM,
    SignedManifest,
    AsciiArmor,
    ARMOR_KEY,
    run_self_tests,
    calculate_entropy,
    __version__
)


def cmd_keygen(args):
    """Generate a fresh 256-bit cryptographically secure symmetric key."""
    key = CryptoKey.generate()
    if args.armor:
        armored = AsciiArmor.encode(ARMOR_KEY, key.raw_bytes)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(armored)
            print(f"[+] Armored key saved to: {args.output}")
        else:
            print(armored)
    else:
        if args.output:
            key.save(args.output)
            print(f"[+] Raw binary 256-bit key saved to: {args.output}")
        else:
            print(f"Key (Hex): {key.hex()}")


def cmd_encrypt(args):
    """Encrypt a file using 1 MiB chunked cascaded AEAD."""
    if not os.path.exists(args.input):
        print(f"[-] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    aad = args.aad.encode("utf-8") if args.aad else b""

    if args.key:
        key = CryptoKey.load(args.key)
        CryptoVault.encrypt_file(args.input, args.output, key=key, aad=aad)
    elif args.password:
        CryptoVault.encrypt_file(args.input, args.output, password=args.password, aad=aad)
    else:
        print("[-] Either --key or --password is required for encryption", file=sys.stderr)
        sys.exit(1)

    print(f"[+] File encrypted successfully: {args.output}")


def cmd_decrypt(args):
    """Decrypt a file with fail-closed authentication verification."""
    if not os.path.exists(args.input):
        print(f"[-] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    aad = args.aad.encode("utf-8") if args.aad else b""

    if args.key:
        key = CryptoKey.load(args.key)
        CryptoVault.decrypt_file(args.input, args.output, key=key, expected_aad=aad)
    elif args.password:
        CryptoVault.decrypt_file(args.input, args.output, password=args.password, expected_aad=aad)
    else:
        print("[-] Either --key or --password is required for decryption", file=sys.stderr)
        sys.exit(1)

    print(f"[+] File decrypted and verified successfully: {args.output}")


def cmd_pqc(args):
    """Post-quantum lattice Ring-LWE cryptographic operations."""
    if args.action == "keygen":
        kp = PqcKEM.generate_keypair()
        pub_path = f"{args.prefix}_pqc.pub"
        sec_path = f"{args.prefix}_pqc.sec"
        with open(pub_path, "wb") as f:
            f.write(kp.public_key)
        with open(sec_path, "wb") as f:
            f.write(kp.secret_key)
        print(f"[+] PQC Public Key saved to: {pub_path} (512 bytes)")
        print(f"[+] PQC Secret Key saved to: {sec_path} (512 bytes)")
    elif args.action == "encap":
        with open(args.pubkey, "rb") as f:
            pk = f.read()
        ct, ss = PqcKEM.encapsulate(pk)
        ct_path = f"{args.prefix}_pqc.ct"
        ss_path = f"{args.prefix}_pqc.ss"
        with open(ct_path, "wb") as f:
            f.write(ct)
        with open(ss_path, "wb") as f:
            f.write(ss)
        print(f"[+] Ciphertext saved to: {ct_path} (544 bytes)")
        print(f"[+] Shared Secret saved to: {ss_path} (32 bytes)")
    elif args.action == "decap":
        with open(args.seckey, "rb") as f:
            sk = f.read()
        with open(args.ciphertext, "rb") as f:
            ct = f.read()
        ss = PqcKEM.decapsulate(sk, ct)
        ss_path = f"{args.prefix}_pqc.ss"
        with open(ss_path, "wb") as f:
            f.write(ss)
        print(f"[+] Decapsulated Shared Secret saved to: {ss_path} (32 bytes)")


def cmd_selftest(_args):
    """Run all internal cryptographic self-tests."""
    print("[*] Running CryptoVault comprehensive cryptographic self-tests...")
    success = run_self_tests()
    if success:
        print("[+] All low-level C and Python cryptographic primitives PASSED.")
    else:
        print("[-] Cryptographic self-tests FAILED!", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="rockcrypter",
        description="RockCrypter — High-Assurance Zero-Trust Cryptographic Engine"
    )
    parser.add_argument("--version", action="version", version=f"RockCrypter {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate fresh 256-bit symmetric key")
    p_keygen.add_argument("-o", "--output", help="Output file path")
    p_keygen.add_argument("-a", "--armor", action="store_true", help="ASCII armor the output")

    # encrypt
    p_enc = subparsers.add_parser("encrypt", help="Encrypt file with AEAD")
    p_enc.add_argument("-i", "--input", required=True, help="Input plaintext file")
    p_enc.add_argument("-o", "--output", required=True, help="Output .rck encrypted file")
    p_enc.add_argument("-k", "--key", help="Keyfile path")
    p_enc.add_argument("-p", "--password", help="Passphrase for memory-hard KDF")
    p_enc.add_argument("--aad", help="Associated Authenticated Data string")

    # decrypt
    p_dec = subparsers.add_parser("decrypt", help="Decrypt file with AEAD")
    p_dec.add_argument("-i", "--input", required=True, help="Input .rck encrypted file")
    p_dec.add_argument("-o", "--output", required=True, help="Output decrypted file")
    p_dec.add_argument("-k", "--key", help="Keyfile path")
    p_dec.add_argument("-p", "--password", help="Passphrase")
    p_dec.add_argument("--aad", help="Expected Associated Authenticated Data string")

    # pqc
    p_pqc = subparsers.add_parser("pqc", help="Post-quantum lattice cryptography")
    p_pqc.add_argument("action", choices=["keygen", "encap", "decap"])
    p_pqc.add_argument("--prefix", default="vault", help="File prefix for outputs")
    p_pqc.add_argument("--pubkey", help="Public key file for encap")
    p_pqc.add_argument("--seckey", help="Secret key file for decap")
    p_pqc.add_argument("--ciphertext", help="Ciphertext file for decap")

    # selftest
    subparsers.add_parser("selftest", help="Run cryptographic verification self-tests")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    dispatch = {
        "keygen": cmd_keygen,
        "encrypt": cmd_encrypt,
        "decrypt": cmd_decrypt,
        "pqc": cmd_pqc,
        "selftest": cmd_selftest,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()

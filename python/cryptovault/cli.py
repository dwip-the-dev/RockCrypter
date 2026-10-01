"""
CryptoVault Command-Line Interface.
"""

import argparse
import sys
import time
import os
from .vault import CryptoKey, CryptoVault
from .binding import CryptoVaultException
from .analysis import analyze_avalanche, calculate_entropy, calculate_chisq, simulate_tamper_suite

def main():
    parser = argparse.ArgumentParser(
        prog="cryptovault",
        description="CryptoVault — Zero-Trust Cryptographic Storage & AEAD Engine"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Keygen
    parser_keygen = subparsers.add_parser("keygen", help="Generate a 256-bit cryptographically secure key")
    parser_keygen.add_argument("-o", "--output", required=True, help="Destination keyfile path")
    parser_keygen.add_argument("--hex", action="store_true", help="Display hex string")

    # Encrypt
    parser_enc = subparsers.add_parser("encrypt", help="Encrypt document or file using chunked streaming AEAD")
    parser_enc.add_argument("-i", "--input", required=True, help="Input file path")
    parser_enc.add_argument("-o", "--output", required=True, help="Encrypted output file path (.cvlt)")
    group_enc = parser_enc.add_mutually_exclusive_group(required=True)
    group_enc.add_argument("-p", "--password", help="Passphrase for memory-hard KDF derivation")
    group_enc.add_argument("-k", "--key", help="Path to 256-bit raw keyfile")
    parser_enc.add_argument("--aad", help="Optional associated metadata to authenticate")
    parser_enc.add_argument("--mem", type=int, default=16384, help="KDF memory cost in KB (default: 16384 KB)")
    parser_enc.add_argument("--time", type=int, default=4, help="KDF iteration cost (default: 4)")

    # Decrypt
    parser_dec = subparsers.add_parser("decrypt", help="Decrypt and authenticate document or file")
    parser_dec.add_argument("-i", "--input", required=True, help="Encrypted input file path (.cvlt)")
    parser_dec.add_argument("-o", "--output", required=True, help="Decrypted output file path")
    group_dec = parser_dec.add_mutually_exclusive_group(required=True)
    group_dec.add_argument("-p", "--password", help="Passphrase")
    group_dec.add_argument("-k", "--key", help="Path to 256-bit raw keyfile")
    parser_dec.add_argument("--aad", help="Expected associated metadata")

    # Analyze
    parser_analyze = subparsers.add_parser("analyze", help="Perform cryptanalytic analysis and statistical evaluation")
    parser_analyze.add_argument("--avalanche", action="store_true", help="Strict Avalanche Criterion (SAC) test")
    parser_analyze.add_argument("--randomness", action="store_true", help="Shannon entropy & Chi-Square test")
    parser_analyze.add_argument("--tamper", action="store_true", help="Zero-trust fault-injection test")
    parser_analyze.add_argument("--all", action="store_true", help="Run all cryptanalytic tests")

    # Benchmark
    subparsers.add_parser("benchmark", help="Measure cryptographic throughput")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "keygen":
            key = CryptoKey.generate()
            key.save(args.output)
            print(f"[+] Successfully generated 256-bit secure key -> {args.output}")
            if args.hex:
                print(f"[+] Key Hex: {key.to_hex()}")

        elif args.command == "encrypt":
            secret = args.password if args.password else CryptoKey.load(args.key)
            print(f"[*] Encrypting '{args.input}' -> '{args.output}'...")
            start_t = time.time()
            CryptoVault.encrypt_document(
                args.input, args.output, secret,
                aad=args.aad, mem_cost_kb=args.mem, time_cost=args.time
            )
            elapsed = time.time() - start_t
            size_mb = os.path.getsize(args.input) / (1024 * 1024)
            speed = size_mb / elapsed if elapsed > 0 else 0
            print(f"[+] Encryption completed in {elapsed:.3f}s ({speed:.2f} MB/s)")

        elif args.command == "decrypt":
            secret = args.password if args.password else CryptoKey.load(args.key)
            print(f"[*] Authenticating and decrypting '{args.input}' -> '{args.output}'...")
            start_t = time.time()
            CryptoVault.decrypt_document(args.input, args.output, secret, expected_aad=args.aad)
            elapsed = time.time() - start_t
            size_mb = os.path.getsize(args.output) / (1024 * 1024)
            speed = size_mb / elapsed if elapsed > 0 else 0
            print(f"[+] Decryption and verification PASSED in {elapsed:.3f}s ({speed:.2f} MB/s)")

        elif args.command == "analyze":
            run_all = args.all or (not args.avalanche and not args.randomness and not args.tamper)

            if args.avalanche or run_all:
                print("\n=== Strict Avalanche Criterion (SAC) Analysis ===")
                res = analyze_avalanche(samples=50)
                print(f"  Trials: {res['total_trials']} 1-bit input flips across {res['samples']} random blocks")
                print(f"  Mean Output Flips: {res['mean_flips']:.2f} / 256 bits ({res['mean_percentage']:.2f}%)")
                print(f"  Ideal: 128.00 bits (50.00%) | StdDev: {res['std_dev_bits']:.2f} bits")
                print(f"  Status: {'PASSED (High Diffusion)' if 48.0 <= res['mean_percentage'] <= 52.0 else 'FAILED'}")

            if args.randomness or run_all:
                print("\n=== Statistical Indistinguishability & Randomness ===")
                key = CryptoKey.generate()
                zero_buf = b"\x00" * (1024 * 1024)
                ct = CryptoVault.encrypt(zero_buf, key, mem_cost_kb=64, time_cost=1)
                entropy = calculate_entropy(ct[sizeof_hdr():])
                chisq = calculate_chisq(ct[sizeof_hdr():])
                print(f"  Shannon Entropy:  {entropy:.6f} bits/byte (Ideal: 8.000000)")
                print(f"  Chi-Square (255): {chisq['chisq']:.2f} (Expected: ~255.0)")
                print(f"  Status: {'PASSED' if entropy > 7.999 else 'FAILED'}")

            if args.tamper or run_all:
                print("\n=== Zero-Trust Tamper Resistance Simulation ===")
                t_res = simulate_tamper_suite()
                print(f"  Total Injected Faults: {t_res['total_tests']}")
                print(f"  Rejected Mutations:    {t_res['rejected']} ({t_res['rejection_rate_pct']:.2f}%)")
                print(f"  Plaintext Leaks:       {t_res['failures']}")
                print(f"  Status: {'PASSED (Zero-Trust Verified)' if t_res['failures'] == 0 else 'COMPROMISED'}")

        elif args.command == "benchmark":
            print("\n=== CryptoVault Throughput Benchmark (Python API) ===")
            key = CryptoKey.generate()
            for size_mb in [1, 5, 20]:
                data = b"\x42" * (size_mb * 1024 * 1024)
                t0 = time.time()
                ct = CryptoVault.encrypt(data, key, mem_cost_kb=64, time_cost=1)
                t_enc = time.time() - t0

                t0 = time.time()
                pt = CryptoVault.decrypt(ct, key)
                t_dec = time.time() - t0
                assert pt == data

                print(f"  Payload {size_mb:2d} MB: Encrypt: {size_mb/t_enc:6.2f} MB/s | Decrypt: {size_mb/t_dec:6.2f} MB/s")

    except CryptoVaultException as e:
        print(f"[-] Cryptographic Security Failure: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)

def sizeof_hdr():
    return 124

if __name__ == "__main__":
    main()

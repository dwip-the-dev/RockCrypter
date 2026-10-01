"""
CryptoVault Statistical Cryptanalysis & Adversarial Fault Injection Suite.
==========================================================================

This test suite executes rigorous cryptanalytic benchmarks and fault injection
simulations on the CryptoVault symmetric core:
1. Strict Avalanche Criterion (SAC) verification for plaintext and keys.
2. Shannon Entropy evaluation against all-zero and all-one plaintext streams.
3. Pearson's Chi-Square Goodness-of-Fit test for uniform distribution indistinguishability.
4. Active adversary fault injection (single-bit flipping, truncation, header tampering).
5. Associated Authenticated Data (AAD) integrity failure verification.
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "python")))

from cryptovault import (
    CryptoKey, CryptoVault, CryptoVaultException,
    calculate_entropy, calculate_chisq,
    analyze_avalanche, simulate_tamper_suite
)

class TestSecurityCryptanalysis(unittest.TestCase):
    """Rigorous empirical cryptanalysis and fault injection test cases."""

    def test_avalanche_criterion(self):
        """Verify Strict Avalanche Criterion (SAC): exactly ~50% bit flip probability."""
        metrics = analyze_avalanche(samples=30)
        self.assertGreaterEqual(metrics["mean_percentage"], 48.0,
                                "Diffusion rate must be at least 48%")
        self.assertLessEqual(metrics["mean_percentage"], 52.0,
                             "Diffusion rate must not exceed 52%")
        self.assertLessEqual(metrics["std_dev_bits"], 12.0,
                             "Avalanche standard deviation must be tight around binomial expectation")

    def test_statistical_randomness(self):
        """Evaluate Shannon entropy and Chi-square statistics on 512 KiB stream."""
        key = CryptoKey.generate()
        zeros = b"\x00" * (512 * 1024)
        ct = CryptoVault.encrypt(zeros, key, mem_cost_kb=64, time_cost=1)
        cipher_stream = ct[96:]  # Payload slice

        entropy = calculate_entropy(cipher_stream)
        chisq = calculate_chisq(cipher_stream)

        # High entropy: indistinguishable from true white noise
        self.assertGreater(entropy, 7.999, "Shannon entropy must exceed 7.999 bits/byte")
        # Chi-square with 255 degrees of freedom: expected range [180.0, 330.0]
        self.assertGreater(chisq["chisq"], 180.0, "Chi-Square statistic below lower critical threshold")
        self.assertLess(chisq["chisq"], 330.0, "Chi-Square statistic exceeds upper critical threshold")

    def test_shannon_entropy_all_ones(self):
        """Verify cipher stream generated from 0xFF bytes exhibits full entropy."""
        key = CryptoKey.generate()
        ones = b"\xFF" * (256 * 1024)
        ct = CryptoVault.encrypt(ones, key, mem_cost_kb=64, time_cost=1)
        cipher_stream = ct[96:]

        entropy = calculate_entropy(cipher_stream)
        self.assertGreater(entropy, 7.998, "Shannon entropy on all-ones plaintext must exceed 7.998")

    def test_fault_injection_tamper_simulation(self):
        """Verify zero-trust tamper resistance under active bit-flipping attacks."""
        results = simulate_tamper_suite()
        self.assertEqual(results["failures"], 0,
                         "No unauthenticated or corrupted bytes must ever decrypt")
        self.assertEqual(results["rejection_rate_pct"], 100.0,
                         "100% of injected ciphertext corruptions must be rejected")

    def test_aad_tamper_resistance(self):
        """Verify that any modification to Associated Authenticated Data is rejected."""
        key = CryptoKey.generate()
        plaintext = b"Highly confidential intelligence dispatch 2026."
        aad_valid = b"Origin:Station-7;Destination:HQ"
        aad_corrupt = b"Origin:Station-8;Destination:HQ"

        ct = CryptoVault.encrypt(plaintext, key, aad=aad_valid, mem_cost_kb=64, time_cost=1)

        # Decryption with correct AAD must succeed
        decrypted = CryptoVault.decrypt(ct, key, expected_aad=aad_valid)
        self.assertEqual(decrypted, plaintext)

        # Decryption with corrupted AAD must raise exception with zero output
        with self.assertRaises(CryptoVaultException):
            CryptoVault.decrypt(ct, key, expected_aad=aad_corrupt)

    def test_header_corruption_immunity(self):
        """Verify that flipping any bit in the envelope header triggers immediate rejection."""
        key = CryptoKey.generate()
        plaintext = b"Payload destined for automated header tamper analysis."
        ct = bytearray(CryptoVault.encrypt(plaintext, key, mem_cost_kb=64, time_cost=1))

        # Corrupt magic byte (offset 0)
        ct[0] ^= 0x01
        with self.assertRaises(CryptoVaultException):
            CryptoVault.decrypt(bytes(ct), key)
        ct[0] ^= 0x01  # Restore

        # Corrupt version byte (offset 8)
        ct[8] ^= 0x01
        with self.assertRaises(CryptoVaultException):
            CryptoVault.decrypt(bytes(ct), key)
        ct[8] ^= 0x01  # Restore

        # Corrupt salt byte (offset 16)
        ct[16] ^= 0x80
        with self.assertRaises(CryptoVaultException):
            CryptoVault.decrypt(bytes(ct), key)

    def test_truncation_detection(self):
        """Verify that truncated envelopes are rejected without releasing plaintext."""
        key = CryptoKey.generate()
        plaintext = b"Full message that will be tested for truncation rejection."
        ct = CryptoVault.encrypt(plaintext, key, mem_cost_kb=64, time_cost=1)

        # Truncate tag (last 16 bytes)
        truncated_tag = ct[:-16]
        with self.assertRaises(CryptoVaultException):
            CryptoVault.decrypt(truncated_tag, key)

        # Truncate half the payload
        truncated_payload = ct[:len(ct) // 2]
        with self.assertRaises(CryptoVaultException):
            CryptoVault.decrypt(truncated_payload, key)

if __name__ == "__main__":
    unittest.main()

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "python")))

from rockcrypter import (
    RockKey, RockCrypter, calculate_entropy, calculate_chisq,
    analyze_avalanche, simulate_tamper_suite
)

class TestSecurityCryptanalysis(unittest.TestCase):
    def test_avalanche_criterion(self):
        # SAC test over 30 samples (7,680 bit flips)
        metrics = analyze_avalanche(samples=30)
        self.assertGreaterEqual(metrics["mean_percentage"], 48.0)
        self.assertLessEqual(metrics["mean_percentage"], 52.0)
        self.assertLessEqual(metrics["std_dev_bits"], 12.0)

    def test_statistical_randomness(self):
        key = RockKey.generate()
        # Encrypt 512 KB of zero bytes (worst-case entropy input)
        zeros = b"\x00" * (512 * 1024)
        ct = RockCrypter.encrypt(zeros, key, mem_cost_kb=64, time_cost=1)
        cipher_stream = ct[96:] # Payload slice

        entropy = calculate_entropy(cipher_stream)
        chisq = calculate_chisq(cipher_stream)

        self.assertGreater(entropy, 7.999)
        self.assertGreater(chisq["chisq"], 180.0)
        self.assertLess(chisq["chisq"], 330.0)

    def test_fault_injection_tamper_simulation(self):
        results = simulate_tamper_suite()
        self.assertEqual(results["failures"], 0, "No unauthenticated or corrupted bytes must ever decrypt")
        self.assertEqual(results["rejection_rate_pct"], 100.0)

if __name__ == "__main__":
    unittest.main()

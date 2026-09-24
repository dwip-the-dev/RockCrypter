import unittest
import os
import tempfile
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "python")))

from rockcrypter import RockKey, RockCrypter, RockException

class TestRockCrypterPython(unittest.TestCase):
    def test_key_generation(self):
        k1 = RockKey.generate()
        k2 = RockKey.generate()
        self.assertEqual(len(k1.to_bytes()), 32)
        self.assertEqual(len(k2.to_bytes()), 32)
        self.assertNotEqual(k1.to_bytes(), k2.to_bytes())

    def test_key_hex_serialization(self):
        k = RockKey.generate()
        hex_val = k.to_hex()
        self.assertEqual(len(hex_val), 64)
        k_reconstructed = RockKey.from_hex(hex_val)
        self.assertEqual(k.to_bytes(), k_reconstructed.to_bytes())

    def test_key_file_save_load(self):
        k = RockKey.generate()
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            k.save(tmp_path)
            loaded = RockKey.load(tmp_path)
            self.assertEqual(k.to_bytes(), loaded.to_bytes())
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_buffer_encryption_raw_key(self):
        key = RockKey.generate()
        secret_data = b"Antigravity zero-trust cryptographic research payload."
        ct = RockCrypter.encrypt(secret_data, key, aad="AuthMetadata:v1")
        self.assertNotEqual(ct, secret_data)

        # Valid decryption
        pt = RockCrypter.decrypt(ct, key, expected_aad="AuthMetadata:v1")
        self.assertEqual(pt, secret_data)

        # Wrong key failure
        wrong_key = RockKey.generate()
        with self.assertRaises(RockException):
            RockCrypter.decrypt(ct, wrong_key, expected_aad="AuthMetadata:v1")

        # Wrong AAD failure
        with self.assertRaises(RockException):
            RockCrypter.decrypt(ct, key, expected_aad="WrongMetadata")

    def test_buffer_encryption_passphrase(self):
        passphrase = "UltraSecurePassword#2026!"
        data = b"Testing memory-hard RockKDF derivation in Python."
        ct = RockCrypter.encrypt(data, passphrase, mem_cost_kb=256, time_cost=2)
        pt = RockCrypter.decrypt(ct, passphrase)
        self.assertEqual(pt, data)

        with self.assertRaises(RockException):
            RockCrypter.decrypt(ct, "WrongPassword")

    def test_streaming_file_roundtrip_and_tamper(self):
        key = RockKey.generate()
        with tempfile.NamedTemporaryFile(delete=False) as f_in, \
             tempfile.NamedTemporaryFile(delete=False) as f_enc, \
             tempfile.NamedTemporaryFile(delete=False) as f_dec:
            in_path = f_in.name
            enc_path = f_enc.name
            dec_path = f_dec.name

        try:
            # Generate 200 KB multi-chunk data
            sample_data = b"ChunkedStreamingRockCrypterData" * 7000
            with open(in_path, "wb") as f:
                f.write(sample_data)

            # Encrypt
            RockCrypter.encrypt_file(in_path, enc_path, key, aad="StreamHeader:1")
            self.assertTrue(os.path.getsize(enc_path) > len(sample_data))

            # Decrypt
            RockCrypter.decrypt_file(enc_path, dec_path, key, expected_aad="StreamHeader:1")
            with open(dec_path, "rb") as f:
                recovered = f.read()
            self.assertEqual(recovered, sample_data)

            # Tamper test: Corrupt a byte in the middle of a chunk
            with open(enc_path, "r+b") as f:
                f.seek(1500)
                b = f.read(1)[0]
                f.seek(1500)
                f.write(bytes([b ^ 0x01]))

            # Decrypt should fail and ensure destination is removed
            with self.assertRaises(RockException):
                RockCrypter.decrypt_file(enc_path, dec_path, key, expected_aad="StreamHeader:1")

            self.assertFalse(os.path.exists(dec_path))

        finally:
            for p in [in_path, enc_path, dec_path]:
                if os.path.exists(p):
                    os.remove(p)

if __name__ == "__main__":
    unittest.main()

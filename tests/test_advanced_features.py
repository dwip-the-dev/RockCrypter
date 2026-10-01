"""
CryptoVault Advanced Subsystems Unit Test Suite (Python).

Validates:
1. Binary Merkle Tree: Tree construction, root consistency, O(log N) proofs, corruption localization.
2. Post-Quantum Cryptography: Ring-LWE lattice keypair generation, encapsulation, decapsulation, hybrid combination.
3. Cryptographic Manifests: .cvman creation, signing, serialization, load, and publisher seal verification.
4. Atomic Storage & Crash Safety: ACID transaction semantics, rollback on abort, chunk offset calculations.
5. Multi-Party Authorization: 2-of-2 dual executive key quorum, multi-recipient key bags, access control.
"""

import os
import unittest
import tempfile
from cryptovault import (
    CryptoKey,
    MerkleTree,
    MerkleProof,
    PqcKEM,
    PqcKeyPair,
    SignedManifest,
    AtomicFileWriter,
    calculate_chunk_offset,
    MultiKeyVault,
    HeisenbergCube,
    CryptoVaultException,
    run_self_tests
)


class TestCryptoVaultAdvanced(unittest.TestCase):
    """Test suite covering advanced subsystems."""

    def test_c_level_self_tests(self):
        """Verify that all C-level cryptographic self-tests report pass."""
        self.assertTrue(run_self_tests(), "Low-level C self-tests must all pass")

    def test_merkle_tree_construction_and_proofs(self):
        """Verify Merkle tree construction, O(log N) authentication proofs, and root verification."""
        # 8 chunk tags of 32 bytes each
        chunk_tags = [os.urandom(32) for _ in range(8)]
        tree = MerkleTree(chunk_tags)

        self.assertEqual(len(tree.root), 32)
        self.assertEqual(tree.num_leaves, 8)

        # Generate and verify proof for chunk 3
        proof = tree.generate_proof(3)
        self.assertEqual(proof.chunk_index, 3)
        self.assertEqual(proof.depth, 3)  # log2(8) = 3
        self.assertTrue(tree.verify_proof(chunk_tags[3], proof))

        # Tampered chunk tag must fail verification
        tampered_tag = bytearray(chunk_tags[3])
        tampered_tag[0] ^= 0xFF
        self.assertFalse(tree.verify_proof(bytes(tampered_tag), proof))

        # Corruption localization
        corrupted_tags = list(chunk_tags)
        corrupted_tags[5] = os.urandom(32)  # Corrupt chunk 5
        corrupt_indices = tree.locate_corruption(corrupted_tags)
        self.assertEqual(corrupt_indices, [5], "Must identify exactly corrupted leaf index")

    def test_post_quantum_kem_roundtrip(self):
        """Verify lattice Ring-LWE keygen, encapsulation, and decapsulation."""
        # Generate PQC keypair
        kp = PqcKEM.generate_keypair()
        self.assertEqual(len(kp.public_key), 512)
        self.assertEqual(len(kp.secret_key), 512)

        # Encapsulate
        ciphertext, ss_sender = PqcKEM.encapsulate(kp.public_key)
        self.assertEqual(len(ciphertext), 544)
        self.assertEqual(len(ss_sender), 32)

        # Decapsulate
        ss_receiver = PqcKEM.decapsulate(kp.secret_key, ciphertext)
        self.assertEqual(len(ss_receiver), 32)
        self.assertEqual(ss_sender, ss_receiver, "Shared secret must match bit-for-bit")

        # Hybrid combiner
        classical_secret = os.urandom(32)
        hybrid_key = PqcKEM.hybrid_combine(classical_secret, ss_receiver)
        self.assertEqual(len(hybrid_key), 32)

    def test_cryptographic_manifest_lifecycle(self):
        """Verify manifest creation, publisher signing, disk serialization, and verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_file = os.path.join(tmpdir, "audit_log.txt")
            manifest_file = os.path.join(tmpdir, "audit_log.cvman")

            with open(sample_file, "wb") as f:
                f.write(b"Audit Log Data: 2026-09-24 Security Audit PASSED")

            # Publisher identity
            pub_key = os.urandom(32)
            priv_key = os.urandom(32)
            merkle_root = os.urandom(32)

            manifest = SignedManifest.create(
                source_path=sample_file,
                publisher_pubkey=pub_key,
                publisher_privkey=priv_key,
                merkle_root=merkle_root,
                chunk_count=1,
                mime_type="text/plain"
            )

            self.assertEqual(manifest.filename, "audit_log.txt")
            self.assertEqual(manifest.mime_type, "text/plain")
            self.assertEqual(manifest.merkle_root, merkle_root)

            # Verify signature with correct pubkey
            self.assertTrue(manifest.verify(pub_key))

            # Verify signature with wrong pubkey
            wrong_pubkey = os.urandom(32)
            self.assertFalse(manifest.verify(wrong_pubkey))

            # Save and Reload
            manifest.save(manifest_file)
            loaded = SignedManifest.load(manifest_file)
            self.assertEqual(loaded.filename, "audit_log.txt")
            self.assertTrue(loaded.verify(pub_key))

    def test_atomic_file_operations_and_rollback(self):
        """Verify crash-safe atomic writing and transaction rollback semantics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "safe_target.dat")

            # Commit test
            with AtomicFileWriter(target) as writer:
                writer.write(b"COMMITTED DATA BLOCK 1")

            self.assertTrue(os.path.exists(target))
            with open(target, "rb") as f:
                self.assertEqual(f.read(), b"COMMITTED DATA BLOCK 1")

            # Abort / exception rollback test
            try:
                with AtomicFileWriter(target) as writer:
                    writer.write(b"CORRUPTED STATE IN FLIGHT")
                    raise RuntimeError("Crash simulation!")
            except RuntimeError:
                pass

            # Target file MUST remain untouched
            with open(target, "rb") as f:
                self.assertEqual(f.read(), b"COMMITTED DATA BLOCK 1", "Original file must not be modified")

            # Offset calculations
            offset_0 = calculate_chunk_offset(0, header_size=128, chunk_payload_size=1048576, tag_size=32)
            self.assertEqual(offset_0, 128)
            offset_1 = calculate_chunk_offset(1, header_size=128, chunk_payload_size=1048576, tag_size=32)
            self.assertEqual(offset_1, 128 + 1048576 + 32)

    def test_multikey_dual_authorization_quorum(self):
        """Verify 2-of-2 dual key encryption and rejection under missing key."""
        payload = b"Top Secret Treaty Ratification Documents 2026"
        key_president = CryptoKey.generate()
        key_senate = CryptoKey.generate()
        unauthorized = CryptoKey.generate()

        container = MultiKeyVault.encrypt_dual(payload, key_president.raw_bytes, key_senate.raw_bytes)

        # Successful joint decryption
        decrypted = MultiKeyVault.decrypt_dual(container, key_president.raw_bytes, key_senate.raw_bytes)
        self.assertEqual(decrypted, payload)

        # Failure when one key is replaced by unauthorized party
        with self.assertRaises(CryptoVaultException):
            MultiKeyVault.decrypt_dual(container, key_president.raw_bytes, unauthorized.raw_bytes)

    def test_multikey_multi_recipient_bag(self):
        """Verify multi-recipient key bag encryption where any valid recipient can unlock."""
        payload = b"Emergency Broadcast System Codes"
        k1 = CryptoKey.generate()
        k2 = CryptoKey.generate()
        k3 = CryptoKey.generate()
        outsider = CryptoKey.generate()

        recipients = [k1.raw_bytes, k2.raw_bytes, k3.raw_bytes]
        container = MultiKeyVault.encrypt_multi_recipient(payload, recipients)

        # All 3 recipients can decrypt independently
        self.assertEqual(MultiKeyVault.decrypt_recipient(container, k1.raw_bytes), payload)
        self.assertEqual(MultiKeyVault.decrypt_recipient(container, k2.raw_bytes), payload)
        self.assertEqual(MultiKeyVault.decrypt_recipient(container, k3.raw_bytes), payload)

        # Outsider is rejected
        with self.assertRaises(CryptoVaultException):
            MultiKeyVault.decrypt_recipient(container, outsider.raw_bytes)

    def test_heisenberg_cube_roundtrip_and_diffusion(self):
        """Verify 16x16x16 (4096-byte) tensor cube and 256x256 (64 KiB) matrix diffusion."""
        key = os.urandom(32)
        cube = HeisenbergCube(key)

        # 1. 4096-byte tensor cube roundtrip
        block = os.urandom(4096)
        transformed = cube.transform_block(block)
        self.assertNotEqual(transformed, block, "Transformed block must differ from plaintext")

        restored = cube.inv_transform_block(transformed)
        self.assertEqual(restored, block, "Inverse transformation must restore plaintext bit-for-bit")

        # 2. 256x256 (65,536-byte) macro-matrix diffusion
        matrix = os.urandom(65536)
        diffused = HeisenbergCube.diffuse_matrix256(matrix, key, is_decryption=False)
        self.assertNotEqual(diffused, matrix, "Diffused matrix must differ thoroughly from input")

        restored_mat = HeisenbergCube.diffuse_matrix256(diffused, key, is_decryption=True)
        self.assertEqual(restored_mat, matrix, "Inverse 256x256 diffusion must restore matrix 100%")


if __name__ == "__main__":
    unittest.main()

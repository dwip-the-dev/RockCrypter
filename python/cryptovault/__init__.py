"""
CryptoVault — High-Assurance Zero-Trust Cryptographic Storage & Transport Suite
=============================================================================

CryptoVault is an advanced, academic capstone-grade cryptographic library
implemented in modern C11 with high-performance Python 3 bindings.

Core Architectural Features:
----------------------------
1. Cascaded Dual-Layer Symmetric Encryption:
   - Layer 1 (Inner): 32-round 256-bit SP-ARX block cipher in Counter (CTR) mode.
   - Layer 2 (Outer): 512-bit wide-state sponge permutation duplex stream cipher.
2. 1 MiB Base Memory-Hard Key Derivation (KDF):
   - 1024 KiB default locked memory matrix to resist GPU/ASIC parallel brute force.
3. 1 MiB Chunked Streaming & Ratcheted Authentication:
   - Processes gigabyte-scale datasets in bounded 1 MiB RAM chunks.
   - Cryptographically ratcheted sponge authentication chain with fail-secure deletion.
4. Asymmetric Hybrid Public-Key Encryption (HPKE):
   - Curve25519 (X25519) Montgomery scalar multiplication.
   - Post-Quantum Ring-LWE Key Encapsulation (Kyber-inspired RLWE over Z_3329[x]/(x^256+1)).
   - NIST SP 800-38F / RFC 3394 SP-ARX Key Wrap algorithm.
5. Information-Theoretic Threshold Secret Sharing:
   - Shamir's Secret Sharing (k-of-n) over Galois Field GF(2^8).
6. Binary Merkle Tree Integrity Verification:
   - O(log N) proofs and instant corruption localization for huge-file random-access.
7. Multi-Party Authorization & Multi-Recipient Key Bags:
   - Dual-key mandatory joint authorization and emergency break-glass recovery.
8. ACID-Safe Atomic File Replacement:
   - Ephemeral staging files, fsync(2) barrier, and atomic POSIX rename(2).
9. Cryptographic Container Manifests:
   - Signed manifests with SHA3-256 tree root, epoch timestamps, and replay protection.
10. RFC 4880 OpenPGP-Style ASCII Armoring:
    - Radix-64 encoding with 24-bit CRC error detection.
"""

from .vault import CryptoKey, CryptoVault
from .binding import CryptoVaultException, strerror, lib
from .shamir import KeyShare, ShamirSecretSharing
from .hybrid import KeyPair, HybridEncryption
from .armor import AsciiArmor, ARMOR_MESSAGE, ARMOR_KEY, ARMOR_SHARE, ARMOR_PUBKEY
from .sharing import SecureSharingWorkflow
from .envelope import EnvelopeHeader
from .transport import OutOfBandTransport
from .merkle import MerkleTree, MerkleProof
from .pqc import PqcKEM, PqcKeyPair
from .manifest import SignedManifest, ManifestSigner
from .atomic import AtomicFileWriter, calculate_chunk_offset, read_chunk_random_access
from .multikey import MultiKeyVault
from .cube import HeisenbergCube
from .analysis import (
    calculate_entropy,
    calculate_chisq,
    analyze_avalanche,
    simulate_tamper_suite
)

__version__ = "2.4.0"
__author__ = "CryptoVault Academic Security Group"
__license__ = "MIT Open-Source Academic License"

__all__ = [
    "CryptoKey",
    "CryptoVault",
    "KeyPair",
    "HybridEncryption",
    "KeyShare",
    "ShamirSecretSharing",
    "AsciiArmor",
    "ARMOR_MESSAGE",
    "ARMOR_KEY",
    "ARMOR_SHARE",
    "ARMOR_PUBKEY",
    "SecureSharingWorkflow",
    "EnvelopeHeader",
    "OutOfBandTransport",
    "CryptoVaultException",
    "strerror",
    "calculate_entropy",
    "calculate_chisq",
    "analyze_avalanche",
    "simulate_tamper_suite",
    "encrypt_file",
    "decrypt_file",
    "generate_key",
    "split_key",
    "combine_shares",
    "run_self_tests",
    "MerkleTree",
    "MerkleProof",
    "PqcKEM",
    "PqcKeyPair",
    "SignedManifest",
    "ManifestSigner",
    "AtomicFileWriter",
    "calculate_chunk_offset",
    "read_chunk_random_access",
    "MultiKeyVault",
    "HeisenbergCube"
]

def generate_key() -> CryptoKey:
    """Generate a high-entropy 256-bit symmetric encryption key."""
    return CryptoKey.generate()

def encrypt_file(in_path: str, out_path: str, password_or_key,
                 aad: bytes = b"", mem_cost_kb: int = 1024, time_cost: int = 4) -> None:
    """
    Encrypt a file using 1 MiB chunked streaming with cascaded dual-layer AEAD.
    
    :param in_path: Path to source plaintext document.
    :param out_path: Destination path for encrypted .cvlt envelope.
    :param password_or_key: String passphrase or CryptoKey instance.
    :param aad: Optional Associated Authenticated Data.
    :param mem_cost_kb: KDF memory cost (default: 1024 KiB = 1 MiB base).
    :param time_cost: KDF iteration count (default: 4 passes).
    """
    if isinstance(password_or_key, CryptoKey):
        CryptoVault.encrypt_file(in_path, out_path, key=password_or_key, aad=aad,
                                 mem_cost_kb=mem_cost_kb, time_cost=time_cost)
    else:
        CryptoVault.encrypt_file(in_path, out_path, password=str(password_or_key), aad=aad,
                                 mem_cost_kb=mem_cost_kb, time_cost=time_cost)

def decrypt_file(in_path: str, out_path: str, password_or_key, aad: bytes = b"") -> None:
    """
    Decrypt and verify a 1 MiB chunked streaming encrypted document.
    Fails securely with automatic deletion if any tampering is detected.
    """
    if isinstance(password_or_key, CryptoKey):
        CryptoVault.decrypt_file(in_path, out_path, key=password_or_key, expected_aad=aad)
    else:
        CryptoVault.decrypt_file(in_path, out_path, password=str(password_or_key), expected_aad=aad)

def split_key(key: CryptoKey, k: int, n: int):
    """Split a 256-bit key into n shares with threshold k."""
    return ShamirSecretSharing.split(key.raw_bytes, k, n)

def combine_shares(shares) -> CryptoKey:
    """Reconstruct a 256-bit key from k valid shares."""
    raw = ShamirSecretSharing.combine(shares)
    return CryptoKey.from_bytes(raw)

def run_self_tests() -> bool:
    """Execute all low-level C cryptographic self-tests across all primitives."""
    # Test SP-ARX block cipher
    if lib.cv_core_self_test() != 0:
        return False
    # Test Sponge permutation
    if lib.cv_sponge_self_test() != 0:
        return False
    # Test GF(2^8) Matrix
    if lib.cv_matrix_self_test() != 0:
        return False
    # Test KDF
    if lib.cv_kdf_self_test() != 0:
        return False
    # Test MAC
    if lib.cv_mac_self_test() != 0:
        return False
    # Test Hash
    if lib.cv_hash_self_test() != 0:
        return False
    # Test HKDF
    if lib.cv_hkdf_self_test() != 0:
        return False
    # Test KeyWrap
    if lib.cv_keywrap_self_test() != 0:
        return False
    # Test X25519 ECDH
    if lib.cv_ecdh_self_test() != 0:
        return False
    # Test Hybrid
    if lib.cv_hybrid_self_test() != 0:
        return False
    # Test Shamir
    if lib.cv_shamir_self_test() != 0:
        return False
    # Test Armoring
    if lib.cv_armor_self_test() != 0:
        return False
    # Test PQC
    if PqcKEM.self_test() is False:
        return False
    # Test Atomic
    if lib.cv_atomic_self_test() != 0:
        return False
    # Test Multi-Key
    if MultiKeyVault.self_test() is False:
        return False
    # Test Heisenberg Cube
    if HeisenbergCube.self_test() is False:
        return False
    return True

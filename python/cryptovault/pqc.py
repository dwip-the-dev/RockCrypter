"""
CryptoVault Post-Quantum Cryptography & Hybrid Key Encapsulation Mechanism.

Implements lattice-based Ring-LWE KEM over R_q = Z_3329[x]/(x^256 + 1) and
dual-PRK hybrid session key combiners (Classical X25519 || Post-Quantum LWE).
"""

import ctypes
from typing import Tuple, Optional
from .binding import lib, CryptoVaultException

CV_PQC_PUBLIC_KEY_SIZE = 512
CV_PQC_SECRET_KEY_SIZE = 512
CV_PQC_CIPHERTEXT_SIZE = 544
CV_PQC_SHARED_SECRET_SIZE = 32

class _CPQCKeypair(ctypes.Structure):
    _fields_ = [
        ("pk", ctypes.c_uint8 * CV_PQC_PUBLIC_KEY_SIZE),
        ("sk", ctypes.c_uint8 * CV_PQC_SECRET_KEY_SIZE),
    ]

class _CPQCCiphertext(ctypes.Structure):
    _fields_ = [
        ("data", ctypes.c_uint8 * CV_PQC_CIPHERTEXT_SIZE),
    ]

# Bind C functions
lib.cv_pqc_keygen.argtypes = [ctypes.POINTER(_CPQCKeypair)]
lib.cv_pqc_keygen.restype = ctypes.c_int

lib.cv_pqc_encapsulate.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(_CPQCCiphertext),
    ctypes.POINTER(ctypes.c_uint8),
]
lib.cv_pqc_encapsulate.restype = ctypes.c_int

lib.cv_pqc_decapsulate.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(_CPQCCiphertext),
    ctypes.POINTER(ctypes.c_uint8),
]
lib.cv_pqc_decapsulate.restype = ctypes.c_int

lib.cv_pqc_hybrid_combine.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
]
lib.cv_pqc_hybrid_combine.restype = ctypes.c_int

lib.cv_pqc_self_test.argtypes = []
lib.cv_pqc_self_test.restype = ctypes.c_int


class PQCKeypair:
    """
    Public and private key container for post-quantum lattice cryptography.
    """
    def __init__(self, public_key: bytes, secret_key: bytes):
        if len(public_key) != CV_PQC_PUBLIC_KEY_SIZE:
            raise ValueError(f"Public key must be {CV_PQC_PUBLIC_KEY_SIZE} bytes")
        if len(secret_key) != CV_PQC_SECRET_KEY_SIZE:
            raise ValueError(f"Secret key must be {CV_PQC_SECRET_KEY_SIZE} bytes")
        self.public_key = public_key
        self.secret_key = secret_key

    def __repr__(self) -> str:
        return f"<PQCKeypair pk={self.public_key[:8].hex()}...>"


class PostQuantumKEM:
    """
    Post-quantum Key Encapsulation Mechanism and Hybrid Combiner.
    """
    @staticmethod
    def generate_keypair() -> PQCKeypair:
        """
        Generate a fresh post-quantum keypair over R_q = Z_3329[x]/(x^256 + 1).
        """
        kp = _CPQCKeypair()
        rc = lib.cv_pqc_keygen(ctypes.byref(kp))
        if rc != 0:
            raise CryptoVaultException(rc, "PQC keygen failed")

        return PQCKeypair(bytes(kp.pk), bytes(kp.sk))

    @staticmethod
    def encapsulate(recipient_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a random 256-bit post-quantum shared secret against recipient public key.
        Returns:
            (ciphertext_bytes, shared_secret_32b)
        """
        if len(recipient_public_key) != CV_PQC_PUBLIC_KEY_SIZE:
            raise ValueError(f"Public key must be {CV_PQC_PUBLIC_KEY_SIZE} bytes")

        pk_c = (ctypes.c_uint8 * CV_PQC_PUBLIC_KEY_SIZE).from_buffer_copy(recipient_public_key)
        ct_c = _CPQCCiphertext()
        ss_c = (ctypes.c_uint8 * CV_PQC_SHARED_SECRET_SIZE)()

        rc = lib.cv_pqc_encapsulate(pk_c, ctypes.byref(ct_c), ss_c)
        if rc != 0:
            raise CryptoVaultException(rc, "PQC encapsulation failed")

        return bytes(ct_c.data), bytes(ss_c)

    @staticmethod
    def decapsulate(recipient_secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate post-quantum shared secret using recipient secret key.
        """
        if len(recipient_secret_key) != CV_PQC_SECRET_KEY_SIZE:
            raise ValueError(f"Secret key must be {CV_PQC_SECRET_KEY_SIZE} bytes")
        if len(ciphertext) != CV_PQC_CIPHERTEXT_SIZE:
            raise ValueError(f"Ciphertext must be {CV_PQC_CIPHERTEXT_SIZE} bytes")

        sk_c = (ctypes.c_uint8 * CV_PQC_SECRET_KEY_SIZE).from_buffer_copy(recipient_secret_key)
        ct_c = _CPQCCiphertext()
        ct_c.data = (ctypes.c_uint8 * CV_PQC_CIPHERTEXT_SIZE).from_buffer_copy(ciphertext)
        ss_c = (ctypes.c_uint8 * CV_PQC_SHARED_SECRET_SIZE)()

        rc = lib.cv_pqc_decapsulate(sk_c, ctypes.byref(ct_c), ss_c)
        if rc != 0:
            raise CryptoVaultException(rc, "PQC decapsulation failed")

        return bytes(ss_c)

    @staticmethod
    def hybrid_combine(
        classical_secret: bytes,
        pqc_secret: bytes,
        context_info: bytes = b"CryptoVault-Hybrid-v2",
        output_len: int = 32
    ) -> bytes:
        """
        Dual-PRK HKDF combiner merging classical Diffie-Hellman and post-quantum secrets.
        """
        out_buf = (ctypes.c_uint8 * output_len)()
        rc = lib.cv_pqc_hybrid_combine(
            classical_secret,
            len(classical_secret),
            pqc_secret,
            len(pqc_secret),
            context_info,
            len(context_info),
            out_buf,
            output_len,
        )
        if rc != 0:
            raise CryptoVaultException(rc, "Hybrid key combination failed")

        return bytes(out_buf)

    @staticmethod
    def self_test() -> bool:
        """
        Execute C-level self-tests for Ring-LWE keygen, encapsulation, and decapsulation.
        """
        return lib.cv_pqc_self_test() == 0


PqcKEM = PostQuantumKEM
PqcKeyPair = PQCKeypair

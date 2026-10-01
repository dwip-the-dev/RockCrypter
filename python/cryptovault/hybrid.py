"""
Python interface for X25519 Hybrid Public-Key Encryption (PKE).
"""

from typing import Union, Optional, Tuple
import ctypes
from .binding import (
    _lib, strerror, CryptoVaultException, CvEcdhKeypair,
    c_uint8, c_size_t, POINTER
)

class KeyPair:
    """Asymmetric X25519 Curve25519 Keypair."""
    def __init__(self, private_bytes: bytes, public_bytes: bytes):
        self.private_key = bytes(private_bytes)
        self.public_key = bytes(public_bytes)

    @classmethod
    def generate(cls) -> "KeyPair":
        kp = CvEcdhKeypair()
        ret = _lib.cv_ecdh_keygen(ctypes.byref(kp))
        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))
        return cls(bytes(kp.priv), bytes(kp.pub))

    @property
    def public_bytes(self) -> bytes:
        return self.public_key

    @property
    def private_bytes(self) -> bytes:
        return self.private_key

    @property
    def public_hex(self) -> str:
        return self.public_key.hex()

    @property
    def private_hex(self) -> str:
        return self.private_key.hex()

    def __repr__(self) -> str:
        return f"<KeyPair X25519 Public={self.public_hex[:16]}...>"


class HybridEncryption:
    """Asymmetric Public-Key Encryption Engine for Secure Transmission."""

    @staticmethod
    def encrypt(recipient_public_key: Union[bytes, str],
                plaintext: Union[bytes, str],
                aad: Optional[Union[bytes, str]] = None) -> bytes:
        """
        Encrypts plaintext for a recipient given their 32-byte X25519 public key.
        """
        pub_bytes = bytes.fromhex(recipient_public_key) if isinstance(recipient_public_key, str) else bytes(recipient_public_key)
        if len(pub_bytes) != 32:
            raise ValueError("Recipient public key must be exactly 32 bytes")

        pt_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        aad_bytes = (aad.encode("utf-8") if isinstance(aad, str) else bytes(aad)) if aad else b""

        c_pub = (c_uint8 * 32).from_buffer_copy(pub_bytes)
        c_pt = (c_uint8 * len(pt_bytes)).from_buffer_copy(pt_bytes) if pt_bytes else None
        c_aad = (c_uint8 * len(aad_bytes)).from_buffer_copy(aad_bytes) if aad_bytes else None

        out_buf = POINTER(c_uint8)()
        out_len = c_size_t(0)

        ret = _lib.cv_hybrid_encrypt(
            c_pub,
            c_pt, len(pt_bytes),
            c_aad, len(aad_bytes),
            ctypes.byref(out_buf),
            ctypes.byref(out_len)
        )
        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))

        try:
            result = bytes(ctypes.string_at(out_buf, out_len.value))
        finally:
            ctypes.CDLL(None).free(out_buf)

        return result

    @staticmethod
    def decrypt(recipient_private_key: Union[bytes, str],
                envelope: bytes,
                expected_aad: Optional[Union[bytes, str]] = None) -> bytes:
        """
        Decrypts a hybrid envelope using recipient's 32-byte X25519 private key.
        """
        priv_bytes = bytes.fromhex(recipient_private_key) if isinstance(recipient_private_key, str) else bytes(recipient_private_key)
        if len(priv_bytes) != 32:
            raise ValueError("Recipient private key must be exactly 32 bytes")

        env_bytes = bytes(envelope)
        aad_bytes = (expected_aad.encode("utf-8") if isinstance(expected_aad, str) else bytes(expected_aad)) if expected_aad else b""

        c_priv = (c_uint8 * 32).from_buffer_copy(priv_bytes)
        c_env = (c_uint8 * len(env_bytes)).from_buffer_copy(env_bytes)
        c_aad = (c_uint8 * len(aad_bytes)).from_buffer_copy(aad_bytes) if aad_bytes else None

        out_pt = POINTER(c_uint8)()
        out_pt_len = c_size_t(0)

        ret = _lib.cv_hybrid_decrypt(
            c_priv,
            c_env, len(env_bytes),
            c_aad, len(aad_bytes),
            ctypes.byref(out_pt),
            ctypes.byref(out_pt_len)
        )
        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))

        try:
            result = bytes(ctypes.string_at(out_pt, out_pt_len.value))
        finally:
            _lib.cv_secure_free(out_pt, out_pt_len.value)

        return result

    @staticmethod
    def encrypt_file(in_path: str, out_path: str,
                     recipient_public_key: Union[bytes, str],
                     aad: Optional[Union[bytes, str]] = None) -> None:
        """
        Encrypts an entire document on disk for a recipient's public key.
        """
        pub_bytes = bytes.fromhex(recipient_public_key) if isinstance(recipient_public_key, str) else bytes(recipient_public_key)
        aad_bytes = (aad.encode("utf-8") if isinstance(aad, str) else bytes(aad)) if aad else b""

        c_in = in_path.encode("utf-8")
        c_out = out_path.encode("utf-8")
        c_pub = (c_uint8 * 32).from_buffer_copy(pub_bytes)
        c_aad = (c_uint8 * len(aad_bytes)).from_buffer_copy(aad_bytes) if aad_bytes else None

        ret = _lib.cv_hybrid_file_encrypt(c_in, c_out, c_pub, c_aad, len(aad_bytes))
        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))

    @staticmethod
    def decrypt_file(in_path: str, out_path: str,
                     recipient_private_key: Union[bytes, str],
                     expected_aad: Optional[Union[bytes, str]] = None) -> None:
        """
        Decrypts an entire document on disk using recipient's private key.
        """
        priv_bytes = bytes.fromhex(recipient_private_key) if isinstance(recipient_private_key, str) else bytes(recipient_private_key)
        aad_bytes = (expected_aad.encode("utf-8") if isinstance(expected_aad, str) else bytes(expected_aad)) if expected_aad else b""

        c_in = in_path.encode("utf-8")
        c_out = out_path.encode("utf-8")
        c_priv = (c_uint8 * 32).from_buffer_copy(priv_bytes)
        c_aad = (c_uint8 * len(aad_bytes)).from_buffer_copy(aad_bytes) if aad_bytes else None

        ret = _lib.cv_hybrid_file_decrypt(c_in, c_out, c_priv, c_aad, len(aad_bytes))
        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))

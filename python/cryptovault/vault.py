"""
High-level Python API for CryptoVault zero-trust authenticated encryption.
"""

import os
import ctypes
from typing import Union, Optional
from .binding import (
    _lib, strerror, CryptoVaultException,
    c_uint8, c_size_t, POINTER
)

class CryptoKey:
    """Represents a 256-bit cryptographically secure key."""
    KEY_SIZE = 32

    def __init__(self, key_bytes: bytes):
        if len(key_bytes) != self.KEY_SIZE:
            raise ValueError(f"CryptoKey must be exactly {self.KEY_SIZE} bytes (got {len(key_bytes)})")
        self._key = bytearray(key_bytes)

    @classmethod
    def generate(cls) -> "CryptoKey":
        buf = (c_uint8 * cls.KEY_SIZE)()
        ret = _lib.cv_entropy_get(buf, cls.KEY_SIZE)
        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))
        return cls(bytes(buf))

    @classmethod
    def from_bytes(cls, b: bytes) -> "CryptoKey":
        return cls(b)

    @classmethod
    def from_hex(cls, hex_str: str) -> "CryptoKey":
        return cls(bytes.fromhex(hex_str.strip()))

    def to_hex(self) -> str:
        return self._key.hex()

    def hex(self) -> str:
        return self._key.hex()

    @property
    def hex_string(self) -> str:
        return self._key.hex()

    def to_bytes(self) -> bytes:
        return bytes(self._key)

    @property
    def raw_bytes(self) -> bytes:
        return bytes(self._key)

    def save(self, filepath: str) -> None:
        with open(filepath, "wb") as f:
            f.write(self._key)

    @classmethod
    def load(cls, filepath: str) -> "CryptoKey":
        with open(filepath, "rb") as f:
            data = f.read(cls.KEY_SIZE)
        return cls(data)

    def zeroize(self) -> None:
        if self._key:
            c_buf = (c_uint8 * len(self._key)).from_buffer(self._key)
            _lib.cv_memzero(c_buf, len(self._key))
            self._key = bytearray()

    def __del__(self):
        self.zeroize()

    def __repr__(self) -> str:
        return "<CryptoKey 256-bit [PROTECTED]>"


class CryptoVault:
    """Zero-Trust AEAD Encryption & Document Protection Engine."""

    @staticmethod
    def _prepare_secret(key_or_pass: Union[CryptoKey, str, bytes]):
        if isinstance(key_or_pass, CryptoKey):
            raw = key_or_pass.to_bytes()
            is_pass = 0
        elif isinstance(key_or_pass, str):
            raw = key_or_pass.encode("utf-8")
            is_pass = 1
        elif isinstance(key_or_pass, (bytes, bytearray)):
            raw = bytes(key_or_pass)
            is_pass = 0 if len(raw) == 32 else 1
        else:
            raise TypeError("key_or_pass must be CryptoKey, str, or bytes")
        return raw, is_pass

    @staticmethod
    def _prepare_aad(aad: Optional[Union[str, bytes]]) -> bytes:
        if aad is None:
            return b""
        if isinstance(aad, str):
            return aad.encode("utf-8")
        return bytes(aad)

    @classmethod
    def encrypt(cls,
                plaintext: Union[str, bytes],
                key_or_pass: Union[CryptoKey, str, bytes],
                aad: Optional[Union[str, bytes]] = None,
                mem_cost_kb: int = 16384,
                time_cost: int = 4) -> bytes:
        """
        Encrypts plaintext in memory into an authenticated envelope.
        """
        pt_bytes = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
        aad_bytes = cls._prepare_aad(aad)
        secret_bytes, is_pass = cls._prepare_secret(key_or_pass)

        c_pt = (c_uint8 * len(pt_bytes)).from_buffer_copy(pt_bytes) if pt_bytes else None
        c_aad = (c_uint8 * len(aad_bytes)).from_buffer_copy(aad_bytes) if aad_bytes else None
        c_secret = (c_uint8 * len(secret_bytes)).from_buffer_copy(secret_bytes)

        out_buf = POINTER(c_uint8)()
        out_len = c_size_t(0)

        ret = _lib.cv_aead_encrypt(
            c_pt, len(pt_bytes),
            c_aad, len(aad_bytes),
            c_secret, len(secret_bytes),
            is_pass,
            mem_cost_kb, time_cost,
            ctypes.byref(out_buf),
            ctypes.byref(out_len)
        )

        _lib.cv_memzero(c_secret, len(secret_bytes))

        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))

        try:
            result = bytes(ctypes.string_at(out_buf, out_len.value))
        finally:
            _lib.cv_secure_free(out_buf, out_len.value)

        return result

    @classmethod
    def decrypt(cls,
                envelope: bytes,
                key_or_pass: Union[CryptoKey, str, bytes],
                expected_aad: Optional[Union[str, bytes]] = None) -> bytes:
        """
        Authenticates and decrypts an envelope buffer.
        Fails securely without releasing partial plaintext on any tamper or error.
        """
        env_bytes = bytes(envelope)
        aad_bytes = cls._prepare_aad(expected_aad)
        secret_bytes, is_pass = cls._prepare_secret(key_or_pass)

        c_env = (c_uint8 * len(env_bytes)).from_buffer_copy(env_bytes)
        c_aad = (c_uint8 * len(aad_bytes)).from_buffer_copy(aad_bytes) if aad_bytes else None
        c_secret = (c_uint8 * len(secret_bytes)).from_buffer_copy(secret_bytes)

        out_pt = POINTER(c_uint8)()
        out_pt_len = c_size_t(0)

        ret = _lib.cv_aead_decrypt(
            c_env, len(env_bytes),
            c_aad, len(aad_bytes),
            c_secret, len(secret_bytes),
            is_pass,
            ctypes.byref(out_pt),
            ctypes.byref(out_pt_len)
        )

        _lib.cv_memzero(c_secret, len(secret_bytes))

        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))

        try:
            result = bytes(ctypes.string_at(out_pt, out_pt_len.value))
        finally:
            if out_pt:
                _lib.cv_secure_free(out_pt, out_pt_len.value)

        return result

    @classmethod
    def encrypt_document(cls,
                         in_path: str,
                         out_path: str,
                         key_or_pass: Optional[Union[CryptoKey, str, bytes]] = None,
                         aad: Optional[Union[str, bytes]] = None,
                         mem_cost_kb: int = 16384,
                         time_cost: int = 4,
                         *,
                         key: Optional[CryptoKey] = None,
                         password: Optional[str] = None) -> None:
        """
        Chunked streaming encryption for documents (PDF, DOCX, binary, text).
        """
        target = key or password or key_or_pass
        if target is None:
            raise ValueError("Must provide key or password")
        aad_bytes = cls._prepare_aad(aad)
        secret_bytes, is_pass = cls._prepare_secret(target)

        c_in = in_path.encode("utf-8")
        c_out = out_path.encode("utf-8")
        c_aad = (c_uint8 * len(aad_bytes)).from_buffer_copy(aad_bytes) if aad_bytes else None
        c_secret = (c_uint8 * len(secret_bytes)).from_buffer_copy(secret_bytes)

        ret = _lib.cv_file_encrypt(
            c_in, c_out,
            c_secret, len(secret_bytes),
            is_pass,
            c_aad, len(aad_bytes),
            mem_cost_kb, time_cost
        )

        _lib.cv_memzero(c_secret, len(secret_bytes))

        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))

    @classmethod
    def decrypt_document(cls,
                         in_path: str,
                         out_path: str,
                         key_or_pass: Optional[Union[CryptoKey, str, bytes]] = None,
                         expected_aad: Optional[Union[str, bytes]] = None,
                         *,
                         key: Optional[CryptoKey] = None,
                         password: Optional[str] = None) -> None:
        """
        Chunked streaming decryption for documents.
        Enforces fail-secure unlinking on any corruption.
        """
        target = key or password or key_or_pass
        if target is None:
            raise ValueError("Must provide key or password")
        aad_bytes = cls._prepare_aad(expected_aad)
        secret_bytes, is_pass = cls._prepare_secret(target)

        c_in = in_path.encode("utf-8")
        c_out = out_path.encode("utf-8")
        c_aad = (c_uint8 * len(aad_bytes)).from_buffer_copy(aad_bytes) if aad_bytes else None
        c_secret = (c_uint8 * len(secret_bytes)).from_buffer_copy(secret_bytes)

        ret = _lib.cv_file_decrypt(
            c_in, c_out,
            c_secret, len(secret_bytes),
            is_pass,
            c_aad, len(aad_bytes)
        )

        _lib.cv_memzero(c_secret, len(secret_bytes))

        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))

    # Aliases for file operations
    encrypt_file = encrypt_document
    decrypt_file = decrypt_document


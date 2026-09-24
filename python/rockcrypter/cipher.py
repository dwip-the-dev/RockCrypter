"""
High-level Python API for RockCrypter zero-trust encryption.
"""

import os
import ctypes
from typing import Union, Optional
from .binding import (
    _lib, strerror, RockException,
    c_uint8, c_size_t, c_char_p, POINTER
)

class RockKey:
    """Represents a 256-bit cryptographically secure key."""
    KEY_SIZE = 32

    def __init__(self, key_bytes: bytes):
        if len(key_bytes) != self.KEY_SIZE:
            raise ValueError(f"RockKey must be exactly {self.KEY_SIZE} bytes (got {len(key_bytes)})")
        self._key = bytearray(key_bytes)

    @classmethod
    def generate(cls) -> "RockKey":
        buf = (c_uint8 * cls.KEY_SIZE)()
        ret = _lib.rock_entropy_get(buf, cls.KEY_SIZE)
        if ret != 0:
            raise RockException(ret, strerror(ret))
        return cls(bytes(buf))

    @classmethod
    def from_bytes(cls, b: bytes) -> "RockKey":
        return cls(b)

    @classmethod
    def from_hex(cls, hex_str: str) -> "RockKey":
        return cls(bytes.fromhex(hex_str.strip()))

    def to_hex(self) -> str:
        return self._key.hex()

    def to_bytes(self) -> bytes:
        return bytes(self._key)

    def save(self, filepath: str) -> None:
        with open(filepath, "wb") as f:
            f.write(self._key)

    @classmethod
    def load(cls, filepath: str) -> "RockKey":
        with open(filepath, "rb") as f:
            data = f.read(cls.KEY_SIZE)
        return cls(data)

    def zeroize(self) -> None:
        if self._key:
            c_buf = (c_uint8 * len(self._key)).from_buffer(self._key)
            _lib.rock_memzero(c_buf, len(self._key))
            self._key = bytearray()

    def __del__(self):
        self.zeroize()

    def __repr__(self) -> str:
        return "<RockKey 256-bit [REDACTED]>"


class RockCrypter:
    """Zero-Trust Multi-Layer AEAD Encryption & Decryption Engine."""

    @staticmethod
    def _prepare_secret(key_or_pass: Union[RockKey, str, bytes]):
        if isinstance(key_or_pass, RockKey):
            raw = key_or_pass.to_bytes()
            is_pass = 0
        elif isinstance(key_or_pass, str):
            raw = key_or_pass.encode("utf-8")
            is_pass = 1
        elif isinstance(key_or_pass, (bytes, bytearray)):
            raw = bytes(key_or_pass)
            is_pass = 0 if len(raw) == 32 else 1
        else:
            raise TypeError("key_or_pass must be RockKey, str, or bytes")
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
                key_or_pass: Union[RockKey, str, bytes],
                aad: Optional[Union[str, bytes]] = None,
                mem_cost_kb: int = 16384,
                time_cost: int = 4) -> bytes:
        """
        Encrypts plaintext in memory with zero-trust authenticated envelope.
        """
        if isinstance(plaintext, str):
            pt_bytes = plaintext.encode("utf-8")
        else:
            pt_bytes = bytes(plaintext)

        aad_bytes = cls._prepare_aad(aad)
        secret_bytes, is_pass = cls._prepare_secret(key_or_pass)

        c_pt = (c_uint8 * len(pt_bytes)).from_buffer_copy(pt_bytes) if pt_bytes else None
        c_aad = (c_uint8 * len(aad_bytes)).from_buffer_copy(aad_bytes) if aad_bytes else None

        c_secret = (c_uint8 * len(secret_bytes)).from_buffer_copy(secret_bytes)

        out_buf = POINTER(c_uint8)()
        out_len = c_size_t(0)

        ret = _lib.rock_aead_encrypt(
            c_pt, len(pt_bytes),
            c_aad, len(aad_bytes),
            c_secret, len(secret_bytes),
            is_pass,
            mem_cost_kb, time_cost,
            ctypes.byref(out_buf),
            ctypes.byref(out_len)
        )

        # Secure zero secret buffer copy
        _lib.rock_memzero(c_secret, len(secret_bytes))

        if ret != 0:
            raise RockException(ret, strerror(ret))

        try:
            result = bytes(ctypes.string_at(out_buf, out_len.value))
        finally:
            _lib.rock_secure_free(out_buf, out_len.value)

        return result

    @classmethod
    def decrypt(cls,
                envelope: bytes,
                key_or_pass: Union[RockKey, str, bytes],
                expected_aad: Optional[Union[str, bytes]] = None) -> bytes:
        """
        Authenticates and decrypts envelope in memory.
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

        ret = _lib.rock_aead_decrypt(
            c_env, len(env_bytes),
            c_aad, len(aad_bytes),
            c_secret, len(secret_bytes),
            is_pass,
            ctypes.byref(out_pt),
            ctypes.byref(out_pt_len)
        )

        _lib.rock_memzero(c_secret, len(secret_bytes))

        if ret != 0:
            raise RockException(ret, strerror(ret))

        try:
            result = bytes(ctypes.string_at(out_pt, out_pt_len.value))
        finally:
            if out_pt:
                _lib.rock_secure_free(out_pt, out_pt_len.value)

        return result

    @classmethod
    def encrypt_file(cls,
                     in_path: str,
                     out_path: str,
                     key_or_pass: Union[RockKey, str, bytes],
                     aad: Optional[Union[str, bytes]] = None,
                     mem_cost_kb: int = 16384,
                     time_cost: int = 4) -> None:
        """
        Streaming file encryption with chunked authentication.
        """
        aad_bytes = cls._prepare_aad(aad)
        secret_bytes, is_pass = cls._prepare_secret(key_or_pass)

        c_in = in_path.encode("utf-8")
        c_out = out_path.encode("utf-8")
        c_aad = (c_uint8 * len(aad_bytes)).from_buffer_copy(aad_bytes) if aad_bytes else None
        c_secret = (c_uint8 * len(secret_bytes)).from_buffer_copy(secret_bytes)

        ret = _lib.rock_file_encrypt(
            c_in, c_out,
            c_secret, len(secret_bytes),
            is_pass,
            c_aad, len(aad_bytes),
            mem_cost_kb, time_cost
        )

        _lib.rock_memzero(c_secret, len(secret_bytes))

        if ret != 0:
            raise RockException(ret, strerror(ret))

    @classmethod
    def decrypt_file(cls,
                     in_path: str,
                     out_path: str,
                     key_or_pass: Union[RockKey, str, bytes],
                     expected_aad: Optional[Union[str, bytes]] = None) -> None:
        """
        Streaming file decryption with chunked authentication.
        Deletes partial output if corrupted or tampered.
        """
        aad_bytes = cls._prepare_aad(expected_aad)
        secret_bytes, is_pass = cls._prepare_secret(key_or_pass)

        c_in = in_path.encode("utf-8")
        c_out = out_path.encode("utf-8")
        c_aad = (c_uint8 * len(aad_bytes)).from_buffer_copy(aad_bytes) if aad_bytes else None
        c_secret = (c_uint8 * len(secret_bytes)).from_buffer_copy(secret_bytes)

        ret = _lib.rock_file_decrypt(
            c_in, c_out,
            c_secret, len(secret_bytes),
            is_pass,
            c_aad, len(aad_bytes)
        )

        _lib.rock_memzero(c_secret, len(secret_bytes))

        if ret != 0:
            raise RockException(ret, strerror(ret))

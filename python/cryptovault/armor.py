"""
CryptoVault ASCII Armoring & Text Serialization Module (RFC 4880 OpenPGP Style).
================================================================================

This module provides high-level Python utilities for converting binary keys,
encrypted messages, and identity certificates into copy-pasteable, email-friendly
ASCII-armored blocks with 24-bit Radix-64 CRC checksums.
"""

from typing import Tuple, Optional
import ctypes
from .binding import lib, CryptoVaultException

# Armor Types
ARMOR_MESSAGE = 1
ARMOR_KEY = 2
ARMOR_SHARE = 3
ARMOR_PUBKEY = 4

class AsciiArmor:
    """High-level ASCII Armoring encoder and decoder with CRC-24 verification."""

    @staticmethod
    def encode(armor_type: int, raw_data: bytes) -> str:
        """
        Encode raw binary data into an RFC 4880 ASCII Armored string.

        :param armor_type: ARMOR_MESSAGE, ARMOR_KEY, ARMOR_SHARE, or ARMOR_PUBKEY.
        :param raw_data: Binary byte string.
        :return: Armored ASCII string.
        """
        if not isinstance(raw_data, (bytes, bytearray)):
            raise TypeError("raw_data must be bytes or bytearray")

        max_len = len(raw_data) * 2 + 1024
        out_buf = ctypes.create_string_buffer(max_len)

        c_data = (ctypes.c_uint8 * len(raw_data)).from_buffer_copy(raw_data)
        ret = lib.cv_armor_encode(
            ctypes.c_int(armor_type),
            c_data,
            ctypes.c_size_t(len(raw_data)),
            out_buf,
            ctypes.c_size_t(max_len)
        )
        if ret != 0:
            raise CryptoVaultException(ret, f"ASCII Armoring encoding failed with code {ret}")

        return out_buf.value.decode("utf-8")

    @staticmethod
    def decode(armored_text: str) -> Tuple[int, bytes]:
        """
        Decode an ASCII Armored string into binary bytes and detected type.
        Verifies headers, base64 payload, and 24-bit CRC checksum.

        :param armored_text: Armored ASCII block.
        :return: Tuple of (detected_armor_type, decoded_binary_bytes).
        """
        if not isinstance(armored_text, str):
            raise TypeError("armored_text must be str")

        text_bytes = armored_text.encode("utf-8")
        capacity = len(text_bytes) + 256
        out_bin = (ctypes.c_uint8 * capacity)()
        out_len = ctypes.c_size_t(capacity)
        detected_type = ctypes.c_int(0)

        ret = lib.cv_armor_decode(
            text_bytes,
            ctypes.byref(detected_type),
            out_bin,
            ctypes.byref(out_len)
        )
        if ret != 0:
            raise CryptoVaultException(ret, f"ASCII Armoring decoding or CRC24 verification failed ({ret})")

        return detected_type.value, bytes(out_bin[:out_len.value])

    @staticmethod
    def encode_key(key_bytes: bytes) -> str:
        """Encode a 256-bit symmetric key into an armored block."""
        return AsciiArmor.encode(ARMOR_KEY, key_bytes)

    @staticmethod
    def decode_key(armored_key: str) -> bytes:
        """Decode an armored key block and verify integrity."""
        armor_type, data = AsciiArmor.decode(armored_key)
        if armor_type != ARMOR_KEY:
            raise ValueError(f"Expected ARMOR_KEY ({ARMOR_KEY}), got {armor_type}")
        return data

    @staticmethod
    def encode_public_key(pubkey_bytes: bytes) -> str:
        """Encode an X25519 public key coordinate into an armored block."""
        return AsciiArmor.encode(ARMOR_PUBKEY, pubkey_bytes)

    @staticmethod
    def decode_public_key(armored_pubkey: str) -> bytes:
        """Decode an armored public key coordinate and verify integrity."""
        armor_type, data = AsciiArmor.decode(armored_pubkey)
        if armor_type != ARMOR_PUBKEY:
            raise ValueError(f"Expected ARMOR_PUBKEY ({ARMOR_PUBKEY}), got {armor_type}")
        return data

    @staticmethod
    def save_file(armored_text: str, file_path: str) -> None:
        """Write armored block to a text file."""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(armored_text)

    @staticmethod
    def load_file(file_path: str) -> str:
        """Read armored block from a text file."""
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()

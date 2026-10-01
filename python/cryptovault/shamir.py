"""
Python interface for Shamir's Secret Sharing (k-of-n threshold scheme).
"""

from typing import List, Union, Optional
import ctypes
from .binding import (
    _lib, strerror, CryptoVaultException, CvShare, c_uint8
)

class KeyShare:
    """Represents an individual k-of-n key share."""
    def __init__(self, share_id: int, data: bytes):
        if not (1 <= share_id <= 255):
            raise ValueError("Share ID must be in [1, 255]")
        if len(data) != 32:
            raise ValueError("Share data must be exactly 32 bytes")
        self.share_id = share_id
        self.data = bytes(data)

    def to_string(self) -> str:
        """Serializes share into human-readable string with CRC32."""
        c_share = CvShare()
        c_share.id = self.share_id
        for i in range(32):
            c_share.data[i] = self.data[i]

        buf = ctypes.create_string_buffer(128)
        ret = _lib.cv_shamir_share_to_string(ctypes.byref(c_share), buf, 128)
        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))
        return buf.value.decode("utf-8")

    def to_formatted_string(self) -> str:
        """Alias for to_string()."""
        return self.to_string()

    @classmethod
    def from_string(cls, s: str) -> "KeyShare":
        """Parses a serialized share string and verifies CRC32 checksum."""
        c_share = CvShare()
        c_str = s.strip().encode("utf-8")
        ret = _lib.cv_shamir_share_from_string(c_str, ctypes.byref(c_share))
        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))
        return cls(c_share.id, bytes(c_share.data))

    def __repr__(self) -> str:
        return f"<KeyShare #{self.share_id} [32 bytes]>"


class ShamirSecretSharing:
    """k-of-n Information-Theoretic Threshold Key Management."""

    @staticmethod
    def split(secret: Union[bytes, bytearray],
              threshold_k: int = 3,
              total_n: int = 5,
              *,
              k: Optional[int] = None,
              n: Optional[int] = None) -> List[KeyShare]:
        """
        Splits a 32-byte secret into n shares requiring k shares to reconstruct.
        """
        if k is not None:
            threshold_k = k
        if n is not None:
            total_n = n
        secret_bytes = bytes(secret)
        if len(secret_bytes) != 32:
            raise ValueError("Secret must be exactly 32 bytes")
        if not (2 <= threshold_k <= total_n <= 255):
            raise ValueError("Must satisfy 2 <= threshold_k <= total_n <= 255")

        c_sec = (c_uint8 * 32).from_buffer_copy(secret_bytes)
        c_shares = (CvShare * total_n)()

        ret = _lib.cv_shamir_split(c_sec, threshold_k, total_n, c_shares)
        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))

        return [KeyShare(c_shares[i].id, bytes(c_shares[i].data)) for i in range(total_n)]

    @staticmethod
    def combine(shares: List[Union[KeyShare, str]]) -> bytes:
        """
        Reconstructs the original 32-byte secret from a list of k valid shares.
        """
        parsed_shares = []
        for s in shares:
            if isinstance(s, str):
                parsed_shares.append(KeyShare.from_string(s))
            elif isinstance(s, KeyShare):
                parsed_shares.append(s)
            else:
                raise TypeError("Shares must be KeyShare objects or formatted strings")

        k = len(parsed_shares)
        if k < 2:
            raise ValueError("Must provide at least 2 shares to combine")

        c_shares = (CvShare * k)()
        for i, s in enumerate(parsed_shares):
            c_shares[i].id = s.share_id
            for b in range(32):
                c_shares[i].data[b] = s.data[b]

        c_sec = (c_uint8 * 32)()
        ret = _lib.cv_shamir_combine(c_shares, k, c_sec)
        if ret != 0:
            raise CryptoVaultException(ret, strerror(ret))

        return bytes(c_sec)

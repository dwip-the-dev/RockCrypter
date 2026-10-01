"""
CryptoVault Multi-Party & Multi-Key Authorization Subsystem.

Implements multi-key key encapsulation mechanisms (KEM) for:
1. Dual-Key (2-of-2) Mandatory Joint Authorization: Requires two independent
   keys (e.g. Corporate Officer + Independent Auditor) to unlock sensitive documents.
   Neither key alone can access the encrypted payload.
2. Multi-Recipient Key Bags: Encapsulates an ephemeral session key under up to
   16 independent recipient public/secret keys or break-glass recovery keys.
3. Fail-Closed Authentication: Rejects forged key slots or modified payloads
   before releasing decrypted plaintext buffers.
"""

import os
import ctypes
from typing import List, Tuple, Optional
from .binding import lib, CryptoVaultException

CV_MULTIKEY_MAGIC = b"CVMK0200"
CV_MULTIKEY_KEY_SIZE = 32
CV_MULTIKEY_WRAPPED_SIZE = 40
CV_MULTIKEY_MAX_SLOTS = 16

CV_MK_SUCCESS = 0
CV_MK_ERR_PARAM = -1
CV_MK_ERR_AUTH = -2
CV_MK_ERR_NOT_FOUND = -3
CV_MK_ERR_SLOT_FULL = -4
CV_MK_ERR_ALLOC = -5
CV_MK_ERR_SELFTEST = -6


class _CKeySlot(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("key_id", ctypes.c_uint8 * 8),
        ("wrapped_session_key", ctypes.c_uint8 * CV_MULTIKEY_WRAPPED_SIZE),
    ]


class _CMultiKeyHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint8 * 8),
        ("version", ctypes.c_uint16),
        ("num_slots", ctypes.c_uint16),
        ("flags", ctypes.c_uint32),
        ("slots", _CKeySlot * CV_MULTIKEY_MAX_SLOTS),
        ("header_mac", ctypes.c_uint8 * 32),
    ]


# Bind C functions
lib.cv_multikey_encrypt_dual.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cv_multikey_encrypt_dual.restype = ctypes.c_int

lib.cv_multikey_decrypt_dual.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cv_multikey_decrypt_dual.restype = ctypes.c_int

lib.cv_multikey_encrypt_multi_recipient.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cv_multikey_encrypt_multi_recipient.restype = ctypes.c_int

lib.cv_multikey_decrypt_recipient.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
    ctypes.POINTER(ctypes.c_size_t),
]
lib.cv_multikey_decrypt_recipient.restype = ctypes.c_int

lib.cv_multikey_self_test.argtypes = []
lib.cv_multikey_self_test.restype = ctypes.c_int


class MultiKeyVault:
    """
    High-assurance multi-key envelope encryption and multi-party quorum management.
    """

    @staticmethod
    def encrypt_dual(plaintext: bytes, key1: bytes, key2: bytes) -> bytes:
        """
        Encrypt data requiring DUAL authorization (2 independent keys).
        Neither key alone possesses sufficient entropy or material to decrypt.
        
        Args:
            plaintext: Raw data to protect
            key1: 32-byte key from first entity (e.g. Officer)
            key2: 32-byte key from second entity (e.g. Auditor)
            
        Returns:
            Encrypted container bytes
        """
        if len(key1) != CV_MULTIKEY_KEY_SIZE or len(key2) != CV_MULTIKEY_KEY_SIZE:
            raise ValueError(f"Both keys must be exactly {CV_MULTIKEY_KEY_SIZE} bytes")

        pt_buf = (ctypes.c_uint8 * len(plaintext)).from_buffer_copy(plaintext)
        k1_buf = (ctypes.c_uint8 * 32).from_buffer_copy(key1)
        k2_buf = (ctypes.c_uint8 * 32).from_buffer_copy(key2)

        out_ptr = ctypes.POINTER(ctypes.c_uint8)()
        out_len = ctypes.c_size_t()

        rc = lib.cv_multikey_encrypt_dual(
            pt_buf, len(plaintext),
            k1_buf, k2_buf,
            ctypes.byref(out_ptr), ctypes.byref(out_len)
        )
        if rc != CV_MK_SUCCESS:
            raise CryptoVaultException(rc, "Dual-key encryption failed")

        try:
            return bytes(ctypes.cast(out_ptr, ctypes.POINTER(ctypes.c_uint8 * out_len.value)).contents)
        finally:
            lib.cv_secure_free(out_ptr, out_len.value)

    @staticmethod
    def decrypt_dual(container: bytes, key1: bytes, key2: bytes) -> bytes:
        """
        Decrypt a dual-authorized container. Requires BOTH keys.
        
        Args:
            container: Encrypted container bytes
            key1: 32-byte key from first entity
            key2: 32-byte key from second entity
            
        Returns:
            Decrypted plaintext bytes
        """
        if len(key1) != CV_MULTIKEY_KEY_SIZE or len(key2) != CV_MULTIKEY_KEY_SIZE:
            raise ValueError(f"Both keys must be exactly {CV_MULTIKEY_KEY_SIZE} bytes")

        ct_buf = (ctypes.c_uint8 * len(container)).from_buffer_copy(container)
        k1_buf = (ctypes.c_uint8 * 32).from_buffer_copy(key1)
        k2_buf = (ctypes.c_uint8 * 32).from_buffer_copy(key2)

        pt_ptr = ctypes.POINTER(ctypes.c_uint8)()
        pt_len = ctypes.c_size_t()

        rc = lib.cv_multikey_decrypt_dual(
            ct_buf, len(container),
            k1_buf, k2_buf,
            ctypes.byref(pt_ptr), ctypes.byref(pt_len)
        )
        if rc != CV_MK_SUCCESS:
            raise CryptoVaultException(rc, "Dual-key decryption failed: invalid keys or corrupted ciphertext")

        try:
            return bytes(ctypes.cast(pt_ptr, ctypes.POINTER(ctypes.c_uint8 * pt_len.value)).contents)
        finally:
            lib.cv_secure_free(pt_ptr, pt_len.value)

    @staticmethod
    def encrypt_multi_recipient(plaintext: bytes, recipient_keys: List[bytes]) -> bytes:
        """
        Encapsulate a file session key for MULTIPLE independent recipients or recovery keys.
        Any single authorized recipient can decrypt the container.
        
        Args:
            plaintext: Raw data to protect
            recipient_keys: List of 32-byte keys (up to 16)
            
        Returns:
            Encrypted container bytes
        """
        if not recipient_keys or len(recipient_keys) > CV_MULTIKEY_MAX_SLOTS:
            raise ValueError(f"Recipients must be between 1 and {CV_MULTIKEY_MAX_SLOTS}")

        for i, k in enumerate(recipient_keys):
            if len(k) != CV_MULTIKEY_KEY_SIZE:
                raise ValueError(f"Recipient key #{i} must be {CV_MULTIKEY_KEY_SIZE} bytes")

        pt_buf = (ctypes.c_uint8 * len(plaintext)).from_buffer_copy(plaintext)
        keys_flat = b"".join(recipient_keys)
        keys_buf = (ctypes.c_uint8 * len(keys_flat)).from_buffer_copy(keys_flat)

        out_ptr = ctypes.POINTER(ctypes.c_uint8)()
        out_len = ctypes.c_size_t()

        rc = lib.cv_multikey_encrypt_multi_recipient(
            pt_buf, len(plaintext),
            keys_buf, len(recipient_keys),
            ctypes.byref(out_ptr), ctypes.byref(out_len)
        )
        if rc != CV_MK_SUCCESS:
            raise CryptoVaultException(rc, "Multi-recipient encryption failed")

        try:
            return bytes(ctypes.cast(out_ptr, ctypes.POINTER(ctypes.c_uint8 * out_len.value)).contents)
        finally:
            lib.cv_secure_free(out_ptr, out_len.value)

    @staticmethod
    def decrypt_recipient(container: bytes, recipient_key: bytes) -> bytes:
        """
        Decrypt a multi-recipient container using ANY ONE valid recipient key or recovery key.
        
        Args:
            container: Encrypted container bytes
            recipient_key: 32-byte key of the recipient
            
        Returns:
            Decrypted plaintext bytes
        """
        if len(recipient_key) != CV_MULTIKEY_KEY_SIZE:
            raise ValueError(f"Recipient key must be {CV_MULTIKEY_KEY_SIZE} bytes")

        ct_buf = (ctypes.c_uint8 * len(container)).from_buffer_copy(container)
        k_buf = (ctypes.c_uint8 * 32).from_buffer_copy(recipient_key)

        pt_ptr = ctypes.POINTER(ctypes.c_uint8)()
        pt_len = ctypes.c_size_t()

        rc = lib.cv_multikey_decrypt_recipient(
            ct_buf, len(container),
            k_buf,
            ctypes.byref(pt_ptr), ctypes.byref(pt_len)
        )
        if rc == CV_MK_ERR_NOT_FOUND:
            raise CryptoVaultException(rc, "Access denied: recipient key not found in authorized key bag")
        if rc != CV_MK_SUCCESS:
            raise CryptoVaultException(rc, "Multi-recipient decryption failed: authentication error or corruption")

        try:
            return bytes(ctypes.cast(pt_ptr, ctypes.POINTER(ctypes.c_uint8 * pt_len.value)).contents)
        finally:
            lib.cv_secure_free(pt_ptr, pt_len.value)

    @staticmethod
    def self_test() -> bool:
        """
        Execute C-level self-tests for dual authorization and multi-recipient encapsulation.
        """
        return lib.cv_multikey_self_test() == CV_MK_SUCCESS

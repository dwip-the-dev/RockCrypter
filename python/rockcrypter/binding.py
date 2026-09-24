"""
ctypes FFI binding for the RockCrypter C core engine.
"""

import os
import sys
import ctypes
from ctypes import c_int, c_uint8, c_uint16, c_uint32, c_uint64, c_size_t, c_char_p, POINTER, Structure

class RockException(Exception):
    """Base exception for RockCrypter errors."""
    def __init__(self, code, message):
        super().__init__(f"RockCrypter Error [{code}]: {message}")
        self.code = code
        self.message = message

def _find_library():
    # 1. Check local repository root
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    local_path = os.path.join(repo_dir, "librockcrypter.so")
    if os.path.exists(local_path):
        return local_path

    # 2. Check current working directory
    cwd_path = os.path.abspath("librockcrypter.so")
    if os.path.exists(cwd_path):
        return cwd_path

    # 3. Fallback to standard library search
    try:
        from ctypes.util import find_library
        lib_name = find_library("rockcrypter")
        if lib_name:
            return lib_name
    except Exception:
        pass

    raise RuntimeError("librockcrypter.so shared library not found. Run 'make' to compile.")

_lib_path = _find_library()
_lib = ctypes.CDLL(_lib_path)

# Error String Lookup
_lib.rock_strerror.argtypes = [c_int]
_lib.rock_strerror.restype = c_char_p

def strerror(code: int) -> str:
    msg = _lib.rock_strerror(code)
    return msg.decode("utf-8") if msg else "Unknown error"

# Memory Zeroization
_lib.rock_memzero.argtypes = [ctypes.c_void_p, c_size_t]
_lib.rock_memzero.restype = None

_lib.rock_secure_free.argtypes = [ctypes.c_void_p, c_size_t]
_lib.rock_secure_free.restype = None

# Entropy Generation
_lib.rock_entropy_get.argtypes = [ctypes.c_void_p, c_size_t]
_lib.rock_entropy_get.restype = c_int

_lib.rock_nonce_generate.argtypes = [POINTER(c_uint8)]
_lib.rock_nonce_generate.restype = c_int

_lib.rock_salt_generate.argtypes = [POINTER(c_uint8)]
_lib.rock_salt_generate.restype = c_int

# Core Cipher Primitives
class RockCoreCtx(Structure):
    _fields_ = [("round_keys", c_uint64 * 4 * 33)]

_lib.rock_core_expand_key.argtypes = [POINTER(RockCoreCtx), POINTER(c_uint8)]
_lib.rock_core_expand_key.restype = c_int

_lib.rock_core_encrypt_block.argtypes = [POINTER(RockCoreCtx), POINTER(c_uint8), POINTER(c_uint8)]
_lib.rock_core_encrypt_block.restype = None

_lib.rock_core_decrypt_block.argtypes = [POINTER(RockCoreCtx), POINTER(c_uint8), POINTER(c_uint8)]
_lib.rock_core_decrypt_block.restype = None

_lib.rock_core_clear.argtypes = [POINTER(RockCoreCtx)]
_lib.rock_core_clear.restype = None

# AEAD Buffer Encryption & Decryption
_lib.rock_aead_encrypt.argtypes = [
    POINTER(c_uint8), c_size_t,           # plaintext, pt_len
    POINTER(c_uint8), c_size_t,           # aad, aad_len
    ctypes.c_void_p, c_size_t,            # secret, secret_len
    c_int,                                # is_passphrase
    c_uint32, c_uint32,                   # mem_cost_kb, time_cost
    POINTER(POINTER(c_uint8)),            # out_buf
    POINTER(c_size_t)                     # out_len
]
_lib.rock_aead_encrypt.restype = c_int

_lib.rock_aead_decrypt.argtypes = [
    POINTER(c_uint8), c_size_t,           # envelope, env_len
    POINTER(c_uint8), c_size_t,           # expected_aad, aad_len
    ctypes.c_void_p, c_size_t,            # secret, secret_len
    c_int,                                # is_passphrase
    POINTER(POINTER(c_uint8)),            # out_plaintext
    POINTER(c_size_t)                     # out_pt_len
]
_lib.rock_aead_decrypt.restype = c_int

# Streaming File Encryption & Decryption
_lib.rock_file_encrypt.argtypes = [
    c_char_p, c_char_p,                   # in_path, out_path
    ctypes.c_void_p, c_size_t,            # secret, secret_len
    c_int,                                # is_passphrase
    POINTER(c_uint8), c_size_t,           # aad, aad_len
    c_uint32, c_uint32                    # mem_cost_kb, time_cost
]
_lib.rock_file_encrypt.restype = c_int

_lib.rock_file_decrypt.argtypes = [
    c_char_p, c_char_p,                   # in_path, out_path
    ctypes.c_void_p, c_size_t,            # secret, secret_len
    c_int,                                # is_passphrase
    POINTER(c_uint8), c_size_t            # expected_aad, aad_len
]
_lib.rock_file_decrypt.restype = c_int

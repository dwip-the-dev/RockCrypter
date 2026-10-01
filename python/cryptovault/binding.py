"""
ctypes FFI binding for the CryptoVault C library.
"""

import os
import ctypes
from ctypes import (
    c_int, c_uint8, c_uint16, c_uint32, c_uint64, c_size_t, c_char_p, POINTER, Structure
)

class CryptoVaultException(Exception):
    """Base exception for CryptoVault errors."""
    def __init__(self, code, message):
        super().__init__(f"CryptoVault Error [{code}]: {message}")
        self.code = code
        self.message = message

def _find_library():
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    local_path = os.path.join(repo_dir, "libcryptovault.so")
    if os.path.exists(local_path):
        return local_path

    cwd_path = os.path.abspath("libcryptovault.so")
    if os.path.exists(cwd_path):
        return cwd_path

    try:
        from ctypes.util import find_library
        lib_name = find_library("cryptovault")
        if lib_name:
            return lib_name
    except Exception:
        pass

    raise RuntimeError("libcryptovault.so not found. Run 'make' to compile.")

_lib_path = _find_library()
_lib = ctypes.CDLL(_lib_path)

# Error string lookup
_lib.cv_strerror.argtypes = [c_int]
_lib.cv_strerror.restype = c_char_p

def strerror(code: int) -> str:
    msg = _lib.cv_strerror(code)
    return msg.decode("utf-8") if msg else "Unknown error"

# Memory zeroization & allocation
_lib.cv_memzero.argtypes = [ctypes.c_void_p, c_size_t]
_lib.cv_memzero.restype = None

_lib.cv_secure_free.argtypes = [ctypes.c_void_p, c_size_t]
_lib.cv_secure_free.restype = None

# Entropy generation
_lib.cv_entropy_get.argtypes = [ctypes.c_void_p, c_size_t]
_lib.cv_entropy_get.restype = c_int

_lib.cv_nonce_generate.argtypes = [POINTER(c_uint8)]
_lib.cv_nonce_generate.restype = None

_lib.cv_salt_generate.argtypes = [POINTER(c_uint8)]
_lib.cv_salt_generate.restype = None

# Core cipher
class CoreCtx(Structure):
    _fields_ = [("round_keys", c_uint64 * 4 * 33)]

_lib.cv_core_expand_key.argtypes = [POINTER(CoreCtx), POINTER(c_uint8)]
_lib.cv_core_expand_key.restype = c_int

_lib.cv_core_encrypt_block.argtypes = [POINTER(CoreCtx), POINTER(c_uint8), POINTER(c_uint8)]
_lib.cv_core_encrypt_block.restype = None

_lib.cv_core_decrypt_block.argtypes = [POINTER(CoreCtx), POINTER(c_uint8), POINTER(c_uint8)]
_lib.cv_core_decrypt_block.restype = None

_lib.cv_core_clear.argtypes = [POINTER(CoreCtx)]
_lib.cv_core_clear.restype = None

# AEAD Buffer
_lib.cv_aead_encrypt.argtypes = [
    POINTER(c_uint8), c_size_t,           # plaintext, pt_len
    POINTER(c_uint8), c_size_t,           # aad, aad_len
    ctypes.c_void_p, c_size_t,            # secret, secret_len
    c_int,                                # is_passphrase
    c_uint32, c_uint32,                   # mem_cost_kb, time_cost
    POINTER(POINTER(c_uint8)),            # out_buf
    POINTER(c_size_t)                     # out_len
]
_lib.cv_aead_encrypt.restype = c_int

_lib.cv_aead_decrypt.argtypes = [
    POINTER(c_uint8), c_size_t,           # envelope, env_len
    POINTER(c_uint8), c_size_t,           # expected_aad, aad_len
    ctypes.c_void_p, c_size_t,            # secret, secret_len
    c_int,                                # is_passphrase
    POINTER(POINTER(c_uint8)),            # out_plaintext
    POINTER(c_size_t)                     # out_pt_len
]
_lib.cv_aead_decrypt.restype = c_int

# Streaming File
_lib.cv_file_encrypt.argtypes = [
    c_char_p, c_char_p,                   # in_path, out_path
    ctypes.c_void_p, c_size_t,            # secret, secret_len
    c_int,                                # is_passphrase
    POINTER(c_uint8), c_size_t,           # aad, aad_len
    c_uint32, c_uint32                    # mem_cost_kb, time_cost
]
_lib.cv_file_encrypt.restype = c_int

_lib.cv_file_decrypt.argtypes = [
    c_char_p, c_char_p,                   # in_path, out_path
    ctypes.c_void_p, c_size_t,            # secret, secret_len
    c_int,                                # is_passphrase
    POINTER(c_uint8), c_size_t            # expected_aad, aad_len
]
_lib.cv_file_decrypt.restype = c_int

# Shamir's Secret Sharing
class CvShare(Structure):
    _fields_ = [
        ("id", c_uint8),
        ("data", c_uint8 * 32)
    ]

_lib.cv_shamir_split.argtypes = [
    POINTER(c_uint8), c_uint8, c_uint8, POINTER(CvShare)
]
_lib.cv_shamir_split.restype = c_int

_lib.cv_shamir_combine.argtypes = [
    POINTER(CvShare), c_uint8, POINTER(c_uint8)
]
_lib.cv_shamir_combine.restype = c_int

_lib.cv_shamir_share_to_string.argtypes = [
    POINTER(CvShare), c_char_p, c_size_t
]
_lib.cv_shamir_share_to_string.restype = c_int

_lib.cv_shamir_share_from_string.argtypes = [
    c_char_p, POINTER(CvShare)
]
_lib.cv_shamir_share_from_string.restype = c_int

# ECDH X25519
class CvEcdhKeypair(Structure):
    _fields_ = [
        ("priv", c_uint8 * 32),
        ("pub", c_uint8 * 32)
    ]

_lib.cv_ecdh_keygen.argtypes = [POINTER(CvEcdhKeypair)]
_lib.cv_ecdh_keygen.restype = c_int

_lib.cv_ecdh_compute_shared.argtypes = [
    POINTER(c_uint8), POINTER(c_uint8), POINTER(c_uint8)
]
_lib.cv_ecdh_compute_shared.restype = c_int

# Key Wrap
_lib.cv_key_wrap.argtypes = [
    POINTER(c_uint8), POINTER(c_uint8), c_size_t, POINTER(c_uint8)
]
_lib.cv_key_wrap.restype = c_int

_lib.cv_key_unwrap.argtypes = [
    POINTER(c_uint8), POINTER(c_uint8), c_size_t, POINTER(c_uint8)
]
_lib.cv_key_unwrap.restype = c_int

# Hybrid PKE
_lib.cv_hybrid_encrypt.argtypes = [
    POINTER(c_uint8), POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t,
    POINTER(POINTER(c_uint8)), POINTER(c_size_t)
]
_lib.cv_hybrid_encrypt.restype = c_int

_lib.cv_hybrid_decrypt.argtypes = [
    POINTER(c_uint8), POINTER(c_uint8), c_size_t,
    POINTER(c_uint8), c_size_t,
    POINTER(POINTER(c_uint8)), POINTER(c_size_t)
]
_lib.cv_hybrid_decrypt.restype = c_int

_lib.cv_hybrid_file_encrypt.argtypes = [
    c_char_p, c_char_p, POINTER(c_uint8), POINTER(c_uint8), c_size_t
]
_lib.cv_hybrid_file_encrypt.restype = c_int

_lib.cv_hybrid_file_decrypt.argtypes = [
    c_char_p, c_char_p, POINTER(c_uint8), POINTER(c_uint8), c_size_t
]
_lib.cv_hybrid_file_decrypt.restype = c_int

# ASCII Armoring
_lib.cv_armor_encode.argtypes = [
    c_int, POINTER(c_uint8), c_size_t, c_char_p, c_size_t
]
_lib.cv_armor_encode.restype = c_int

_lib.cv_armor_decode.argtypes = [
    c_char_p, POINTER(c_int), POINTER(c_uint8), POINTER(c_size_t)
]
_lib.cv_armor_decode.restype = c_int

# Cryptographic Hash
_lib.cv_hash256.argtypes = [ctypes.c_void_p, c_size_t, POINTER(c_uint8)]
_lib.cv_hash256.restype = c_int

_lib.cv_hash512.argtypes = [ctypes.c_void_p, c_size_t, POINTER(c_uint8)]
_lib.cv_hash512.restype = c_int

# Package Container (.cvpkg)
_lib.cv_package_create_hybrid.argtypes = [c_char_p, c_char_p, POINTER(c_uint8)]
_lib.cv_package_create_hybrid.restype = c_int

_lib.cv_package_extract_hybrid.argtypes = [c_char_p, c_char_p, POINTER(c_uint8)]
_lib.cv_package_extract_hybrid.restype = c_int

_lib.cv_package_create_password.argtypes = [c_char_p, c_char_p, c_char_p]
_lib.cv_package_create_password.restype = c_int

_lib.cv_package_extract_password.argtypes = [c_char_p, c_char_p, c_char_p]
_lib.cv_package_extract_password.restype = c_int

# Self-Tests
_lib.cv_core_self_test.argtypes = []
_lib.cv_core_self_test.restype = c_int

_lib.cv_sponge_self_test.argtypes = []
_lib.cv_sponge_self_test.restype = c_int

_lib.cv_matrix_self_test.argtypes = []
_lib.cv_matrix_self_test.restype = c_int

_lib.cv_kdf_self_test.argtypes = []
_lib.cv_kdf_self_test.restype = c_int

_lib.cv_mac_self_test.argtypes = []
_lib.cv_mac_self_test.restype = c_int

_lib.cv_hash_self_test.argtypes = []
_lib.cv_hash_self_test.restype = c_int

_lib.cv_hkdf_self_test.argtypes = []
_lib.cv_hkdf_self_test.restype = c_int

_lib.cv_keywrap_self_test.argtypes = []
_lib.cv_keywrap_self_test.restype = c_int

_lib.cv_ecdh_self_test.argtypes = []
_lib.cv_ecdh_self_test.restype = c_int

_lib.cv_hybrid_self_test.argtypes = []
_lib.cv_hybrid_self_test.restype = c_int

_lib.cv_shamir_self_test.argtypes = []
_lib.cv_shamir_self_test.restype = c_int

_lib.cv_armor_self_test.argtypes = []
_lib.cv_armor_self_test.restype = c_int

lib = _lib

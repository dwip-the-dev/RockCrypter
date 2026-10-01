"""
RockCrypter 256x256 Multi-Dimensional Cube & Heisenberg Tensor Diffusion Engine.

Provides Python bindings for:
1. 16x16x16 (4096-byte) Tensor Hypercube Transformation:
   Applies non-commutative position-momentum phase shifts and 3-axis rotational permutations.
2. 256x256 (65,536-byte) Macro-Matrix Diffusion:
   Diffuses 64 KiB memory buffers in a single algebraic pass with exact invertible bijection.
"""

import os
import ctypes
from typing import Optional
from .binding import lib, CryptoVaultException

CV_CUBE_DIM = 16
CV_CUBE_SIZE = 4096            # 16 * 16 * 16 bytes
CV_MATRIX_256_DIM = 256
CV_MATRIX_256_SIZE = 65536      # 256 * 256 bytes
CV_CUBE_KEY_SIZE = 32

CV_CUBE_SUCCESS = 0
CV_CUBE_ERR_PARAM = -1
CV_CUBE_ERR_ALLOC = -2
CV_CUBE_ERR_CORRUPT = -3
CV_CUBE_ERR_SELFTEST = -4


class _CHeisenbergState(ctypes.Structure):
    _fields_ = [
        ("phase_x", ctypes.c_uint8 * CV_CUBE_DIM),
        ("phase_p", ctypes.c_uint8 * CV_CUBE_DIM),
        ("commutator_seed", ctypes.c_uint8 * CV_CUBE_KEY_SIZE),
    ]


class _CCubeCtx(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint8 * CV_CUBE_SIZE),
        ("round_keys", (ctypes.c_uint8 * CV_CUBE_KEY_SIZE) * 8),
        ("heisenberg", _CHeisenbergState),
        ("initialized", ctypes.c_int),
    ]


# Bind C functions
lib.cv_cube_init.argtypes = [ctypes.POINTER(_CCubeCtx), ctypes.POINTER(ctypes.c_uint8)]
lib.cv_cube_init.restype = ctypes.c_int

lib.cv_cube_transform_block.argtypes = [
    ctypes.POINTER(_CCubeCtx),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
]
lib.cv_cube_transform_block.restype = ctypes.c_int

lib.cv_cube_inv_transform_block.argtypes = [
    ctypes.POINTER(_CCubeCtx),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
]
lib.cv_cube_inv_transform_block.restype = ctypes.c_int

lib.cv_cube_matrix256_diffuse.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_int,
]
lib.cv_cube_matrix256_diffuse.restype = ctypes.c_int

lib.cv_cube_clear.argtypes = [ctypes.POINTER(_CCubeCtx)]
lib.cv_cube_clear.restype = None

lib.cv_cube_self_test.argtypes = []
lib.cv_cube_self_test.restype = ctypes.c_int


class HeisenbergCube:
    """
    RockCrypter 256x256 & 16x16x16 Cube Transformation Engine.
    """

    def __init__(self, key: bytes):
        if len(key) != CV_CUBE_KEY_SIZE:
            raise ValueError(f"Key must be exactly {CV_CUBE_KEY_SIZE} bytes")

        self._ctx = _CCubeCtx()
        key_buf = (ctypes.c_uint8 * CV_CUBE_KEY_SIZE).from_buffer_copy(key)

        rc = lib.cv_cube_init(ctypes.byref(self._ctx), key_buf)
        if rc != CV_CUBE_SUCCESS:
            raise CryptoVaultException(rc, "Failed to initialize Heisenberg Cube context")

    def __del__(self):
        if hasattr(self, "_ctx") and self._ctx.initialized:
            lib.cv_cube_clear(ctypes.byref(self._ctx))

    def transform_block(self, in_bytes: bytes) -> bytes:
        """
        Apply forward Heisenberg Cube transformation on a 4096-byte block.
        """
        if len(in_bytes) != CV_CUBE_SIZE:
            raise ValueError(f"Block size must be exactly {CV_CUBE_SIZE} bytes")

        in_buf = (ctypes.c_uint8 * CV_CUBE_SIZE).from_buffer_copy(in_bytes)
        out_buf = (ctypes.c_uint8 * CV_CUBE_SIZE)()

        rc = lib.cv_cube_transform_block(ctypes.byref(self._ctx), in_buf, out_buf)
        if rc != CV_CUBE_SUCCESS:
            raise CryptoVaultException(rc, "Forward cube transformation failed")

        return bytes(out_buf)

    def inv_transform_block(self, in_bytes: bytes) -> bytes:
        """
        Apply inverse Heisenberg Cube transformation to reverse the 4096-byte block.
        """
        if len(in_bytes) != CV_CUBE_SIZE:
            raise ValueError(f"Block size must be exactly {CV_CUBE_SIZE} bytes")

        in_buf = (ctypes.c_uint8 * CV_CUBE_SIZE).from_buffer_copy(in_bytes)
        out_buf = (ctypes.c_uint8 * CV_CUBE_SIZE)()

        rc = lib.cv_cube_inv_transform_block(ctypes.byref(self._ctx), in_buf, out_buf)
        if rc != CV_CUBE_SUCCESS:
            raise CryptoVaultException(rc, "Inverse cube transformation failed")

        return bytes(out_buf)

    @staticmethod
    def diffuse_matrix256(data: bytes, key: bytes, is_decryption: bool = False) -> bytes:
        """
        Execute 256x256 (65,536-byte) Macro-Matrix Heisenberg diffusion.
        """
        if len(data) != CV_MATRIX_256_SIZE:
            raise ValueError(f"Data size must be exactly {CV_MATRIX_256_SIZE} bytes")
        if len(key) != CV_CUBE_KEY_SIZE:
            raise ValueError(f"Key must be exactly {CV_CUBE_KEY_SIZE} bytes")

        buf = (ctypes.c_uint8 * CV_MATRIX_256_SIZE).from_buffer_copy(data)
        key_buf = (ctypes.c_uint8 * CV_CUBE_KEY_SIZE).from_buffer_copy(key)

        rc = lib.cv_cube_matrix256_diffuse(buf, key_buf, 1 if is_decryption else 0)
        if rc != CV_CUBE_SUCCESS:
            raise CryptoVaultException(rc, "256x256 matrix diffusion failed")

        return bytes(buf)

    @staticmethod
    def self_test() -> bool:
        """
        Execute C-level self-tests for Heisenberg cube and 256x256 matrix diffusion.
        """
        return lib.cv_cube_self_test() == CV_CUBE_SUCCESS

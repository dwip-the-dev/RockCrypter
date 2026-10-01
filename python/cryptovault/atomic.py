"""
CryptoVault Crash-Safe Storage & Atomic File Operations Subsystem.

Provides ACID-like guarantees for encrypted file updates:
- Ephemeral staging files on the same filesystem
- Synchronous physical disk flush via fsync(2)
- Atomic namespace swap via POSIX rename(2)
- Automatic crash and tamper rollback: authentic files are never corrupted
- 64-bit huge-file random-access chunk reader
"""

import os
import ctypes
from typing import Optional
from .binding import lib, CryptoVaultException

CV_ATOMIC_SUCCESS = 0
CV_ATOMIC_ERR_PARAM = -1
CV_ATOMIC_ERR_IO = -2
CV_ATOMIC_ERR_SYNC = -3
CV_ATOMIC_ERR_RENAME = -4
CV_ATOMIC_ERR_SEEK = -5
CV_ATOMIC_ERR_SELFTEST = -6

CHUNK_PAYLOAD_SIZE = 1048576  # 1 MiB chunk payload
CHUNK_TAG_SIZE = 32           # 32-byte chunk MAC tag


class _CAtomicFile(ctypes.Structure):
    _fields_ = [
        ("target_path", ctypes.c_char * 512),
        ("temp_path", ctypes.c_char * 540),
        ("file_handle", ctypes.c_void_p),
        ("is_open", ctypes.c_int),
    ]


# Bind atomic functions
lib.cv_atomic_begin.argtypes = [ctypes.POINTER(_CAtomicFile), ctypes.c_char_p]
lib.cv_atomic_begin.restype = ctypes.c_int

lib.cv_atomic_write.argtypes = [ctypes.POINTER(_CAtomicFile), ctypes.c_void_p, ctypes.c_size_t]
lib.cv_atomic_write.restype = ctypes.c_int

lib.cv_atomic_commit.argtypes = [ctypes.POINTER(_CAtomicFile)]
lib.cv_atomic_commit.restype = ctypes.c_int

lib.cv_atomic_abort.argtypes = [ctypes.POINTER(_CAtomicFile)]
lib.cv_atomic_abort.restype = None

lib.cv_calc_chunk_offset.argtypes = [ctypes.c_uint64, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t]
lib.cv_calc_chunk_offset.restype = ctypes.c_uint64

lib.cv_read_chunk_random_access.argtypes = [
    ctypes.c_char_p,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_uint8),
]
lib.cv_read_chunk_random_access.restype = ctypes.c_int

lib.cv_atomic_self_test.argtypes = []
lib.cv_atomic_self_test.restype = ctypes.c_int


class AtomicFileWriter:
    """
    Context manager for crash-safe atomic encrypted writes.
    Stages data in an ephemeral temporary file, flushes to disk via fsync(2),
    and atomically replaces the target file via rename(2) upon successful exit.
    If an unhandled exception or abort occurs, the staging file is unlinked immediately.
    """

    def __init__(self, target_path: str):
        self.target_path = os.path.abspath(target_path)
        self._c_af = _CAtomicFile()
        self._committed = False

    def __enter__(self):
        rc = lib.cv_atomic_begin(ctypes.byref(self._c_af), self.target_path.encode("utf-8"))
        if rc != CV_ATOMIC_SUCCESS:
            raise CryptoVaultException(rc, f"Failed to begin atomic write to {self.target_path}")
        return self

    def write(self, data: bytes) -> int:
        """
        Write binary data to the atomic staging file.
        """
        if not self._c_af.is_open:
            raise IOError("Atomic file transaction is not open")
        if not data:
            return 0

        buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        rc = lib.cv_atomic_write(ctypes.byref(self._c_af), buf, len(data))
        if rc != CV_ATOMIC_SUCCESS:
            raise CryptoVaultException(rc, "I/O error during atomic write")
        return len(data)

    def commit(self):
        """
        Explicitly commit the atomic transaction: fsync to storage media and rename.
        """
        if self._committed:
            return
        rc = lib.cv_atomic_commit(ctypes.byref(self._c_af))
        if rc != CV_ATOMIC_SUCCESS:
            raise CryptoVaultException(rc, f"Failed to commit atomic write to {self.target_path}")
        self._committed = True

    def abort(self):
        """
        Abort the atomic transaction, closing handles and removing temporary scratch files.
        """
        if self._c_af.is_open:
            lib.cv_atomic_abort(ctypes.byref(self._c_af))
        self._committed = False

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.abort()
        else:
            if not self._committed:
                self.commit()


def calculate_chunk_offset(
    chunk_index: int,
    header_size: int = 128,
    chunk_payload_size: int = CHUNK_PAYLOAD_SIZE,
    tag_size: int = CHUNK_TAG_SIZE,
) -> int:
    """
    Calculate the exact 64-bit byte offset for an encrypted chunk.
    """
    return int(lib.cv_calc_chunk_offset(chunk_index, header_size, chunk_payload_size, tag_size))


def read_chunk_random_access(
    file_path: str,
    chunk_index: int,
    header_size: int = 128,
    chunk_payload_size: int = CHUNK_PAYLOAD_SIZE,
    tag_size: int = CHUNK_TAG_SIZE,
) -> tuple[bytes, bytes]:
    """
    Read an individual encrypted chunk and its 32-byte authentication tag
    at an arbitrary 64-bit file offset in O(1) time without sequential decoding.
    
    Returns:
        (encrypted_chunk_bytes, mac_tag_32_bytes)
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    offset = calculate_chunk_offset(chunk_index, header_size, chunk_payload_size, tag_size)
    chunk_buf = (ctypes.c_uint8 * chunk_payload_size)()
    tag_buf = (ctypes.c_uint8 * tag_size)()

    rc = lib.cv_read_chunk_random_access(
        file_path.encode("utf-8"),
        ctypes.c_uint64(offset),
        chunk_buf,
        chunk_payload_size,
        tag_buf,
    )
    if rc != CV_ATOMIC_SUCCESS:
        raise CryptoVaultException(rc, f"Failed to read chunk {chunk_index} at offset {offset}")

    return bytes(chunk_buf), bytes(tag_buf)


def atomic_self_test() -> bool:
    """
    Execute C-level self-tests for crash recovery, rollback, and offset calculations.
    """
    return lib.cv_atomic_self_test() == CV_ATOMIC_SUCCESS

"""
CryptoVault Cryptographic Manifest (.cvman) Subsystem.

Creates, signs, serializes, and verifies tamper-evident file manifests binding
filename, MIME type, POSIX permissions, Merkle roots, and publisher seals.
"""

import os
import ctypes
from typing import Optional
from .binding import lib, CryptoVaultException

CV_MANIFEST_MAX_NAME = 128
CV_MANIFEST_MAX_MIME = 32
CV_MANIFEST_SIG_SIZE = 32

class _CManifest(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint8 * 8),
        ("version", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("posix_mode", ctypes.c_uint32),
        ("file_size_bytes", ctypes.c_uint64),
        ("chunk_count", ctypes.c_uint64),
        ("created_timestamp", ctypes.c_uint64),
        ("orig_filename", ctypes.c_char * CV_MANIFEST_MAX_NAME),
        ("mime_type", ctypes.c_char * CV_MANIFEST_MAX_MIME),
        ("publisher_pubkey", ctypes.c_uint8 * 32),
        ("full_file_hash", ctypes.c_uint8 * 32),
        ("merkle_root", ctypes.c_uint8 * 32),
        ("manifest_seal", ctypes.c_uint8 * CV_MANIFEST_SIG_SIZE),
    ]

# Bind C functions
lib.cv_manifest_create.argtypes = [
    ctypes.POINTER(_CManifest),
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_uint64,
]
lib.cv_manifest_create.restype = ctypes.c_int

lib.cv_manifest_verify.argtypes = [
    ctypes.POINTER(_CManifest),
    ctypes.POINTER(ctypes.c_uint8),
]
lib.cv_manifest_verify.restype = ctypes.c_int

lib.cv_manifest_save.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(_CManifest),
]
lib.cv_manifest_save.restype = ctypes.c_int

lib.cv_manifest_load.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(_CManifest),
]
lib.cv_manifest_load.restype = ctypes.c_int

lib.cv_manifest_self_test.argtypes = []
lib.cv_manifest_self_test.restype = ctypes.c_int


class CryptoManifest:
    """
    Cryptographic manifest guaranteeing authenticated metadata and Merkle roots.
    """
    def __init__(self, raw_c_manifest: _CManifest):
        self._c = raw_c_manifest

    @property
    def filename(self) -> str:
        return self._c.orig_filename.decode("utf-8", errors="replace")

    @property
    def mime_type(self) -> str:
        return self._c.mime_type.decode("utf-8", errors="replace")

    @property
    def posix_mode(self) -> int:
        return self._c.posix_mode

    @property
    def file_size(self) -> int:
        return self._c.file_size_bytes

    @property
    def chunk_count(self) -> int:
        return self._c.chunk_count

    @property
    def merkle_root(self) -> bytes:
        return bytes(self._c.merkle_root)

    @property
    def manifest_seal(self) -> bytes:
        return bytes(self._c.manifest_seal)

    @classmethod
    def create(
        cls,
        source_path: str,
        publisher_pubkey: bytes,
        publisher_privkey: bytes,
        merkle_root: bytes,
        chunk_count: int = 1,
        orig_name: Optional[str] = None,
        mime_type: str = "application/octet-stream"
    ) -> "CryptoManifest":
        """
        Create and sign a cryptographic manifest for a target file.
        """
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source file not found: {source_path}")
        if len(publisher_pubkey) != 32 or len(publisher_privkey) != 32:
            raise ValueError("Keys must be 32 bytes")
        if len(merkle_root) != 32:
            raise ValueError("Merkle root must be 32 bytes")

        name = orig_name if orig_name else os.path.basename(source_path)

        c_man = _CManifest()
        pub_c = (ctypes.c_uint8 * 32).from_buffer_copy(publisher_pubkey)
        priv_c = (ctypes.c_uint8 * 32).from_buffer_copy(publisher_privkey)
        root_c = (ctypes.c_uint8 * 32).from_buffer_copy(merkle_root)

        rc = lib.cv_manifest_create(
            ctypes.byref(c_man),
            source_path.encode("utf-8"),
            name.encode("utf-8"),
            mime_type.encode("utf-8"),
            pub_c,
            priv_c,
            root_c,
            chunk_count
        )
        if rc != 0:
            raise CryptoVaultException(rc, "Failed to create manifest")

        return cls(c_man)

    def verify(self, expected_publisher_pubkey: bytes) -> bool:
        """
        Verify the publisher seal of this manifest.
        """
        if len(expected_publisher_pubkey) != 32:
            raise ValueError("Public key must be 32 bytes")

        pub_c = (ctypes.c_uint8 * 32).from_buffer_copy(expected_publisher_pubkey)
        rc = lib.cv_manifest_verify(ctypes.byref(self._c), pub_c)
        return rc == 0

    def save(self, dest_path: str):
        """
        Write manifest structure to a .cvman file.
        """
        rc = lib.cv_manifest_save(dest_path.encode("utf-8"), ctypes.byref(self._c))
        if rc != 0:
            raise CryptoVaultException(rc, f"Failed to save manifest to {dest_path}")

    @classmethod
    def load(cls, manifest_path: str) -> "CryptoManifest":
        """
        Read and deserialize a manifest file from disk.
        """
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(f"Manifest not found: {manifest_path}")

        c_man = _CManifest()
        rc = lib.cv_manifest_load(manifest_path.encode("utf-8"), ctypes.byref(c_man))
        if rc != 0:
            raise CryptoVaultException(rc, f"Failed to load manifest from {manifest_path}")

        return cls(c_man)

    @staticmethod
    def self_test() -> bool:
        """
        Execute C-level self-tests for manifest generation, serialization, and verification.
        """
        return lib.cv_manifest_self_test() == 0


SignedManifest = CryptoManifest
ManifestSigner = CryptoManifest

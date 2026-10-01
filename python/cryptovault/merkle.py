"""
CryptoVault Binary Merkle Tree Verification & Random-Access Integrity Subsystem.

Provides logarithmic O(log N) authentication proofs, second-preimage resistance,
and corruption localization for huge-file random-access decryption.
"""

import os
import ctypes
from typing import List, Tuple, Optional
from .binding import lib, CryptoVaultException

CV_MERKLE_HASH_SIZE = 32
CV_MERKLE_MAX_DEPTH = 32

class _CMerkleTree(ctypes.Structure):
    _fields_ = [
        ("num_leaves", ctypes.c_size_t),
        ("total_nodes", ctypes.c_size_t),
        ("nodes", ctypes.c_void_p),
        ("root", ctypes.c_uint8 * CV_MERKLE_HASH_SIZE),
    ]

class _CMerkleProof(ctypes.Structure):
    _fields_ = [
        ("chunk_index", ctypes.c_uint64),
        ("depth", ctypes.c_size_t),
        ("siblings", (ctypes.c_uint8 * CV_MERKLE_HASH_SIZE) * CV_MERKLE_MAX_DEPTH),
    ]

# Bind C functions
lib.cv_merkle_build.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(_CMerkleTree)]
lib.cv_merkle_build.restype = ctypes.c_int

lib.cv_merkle_free.argtypes = [ctypes.POINTER(_CMerkleTree)]
lib.cv_merkle_free.restype = None

lib.cv_merkle_get_root.argtypes = [ctypes.POINTER(_CMerkleTree), ctypes.POINTER(ctypes.c_uint8)]
lib.cv_merkle_get_root.restype = ctypes.c_int

lib.cv_merkle_gen_proof.argtypes = [ctypes.POINTER(_CMerkleTree), ctypes.c_uint64, ctypes.POINTER(_CMerkleProof)]
lib.cv_merkle_gen_proof.restype = ctypes.c_int

lib.cv_merkle_verify_proof.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(_CMerkleProof)]
lib.cv_merkle_verify_proof.restype = ctypes.c_int

lib.cv_merkle_locate_corruption.argtypes = [
    ctypes.POINTER(_CMerkleTree),
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)
]
lib.cv_merkle_locate_corruption.restype = ctypes.c_int


class MerkleProof:
    """
    Logarithmic O(log N) Merkle authentication proof for a specific chunk.
    """
    def __init__(self, chunk_index: int, depth: int, siblings: List[bytes]):
        self.chunk_index = chunk_index
        self.depth = depth
        self.siblings = siblings

    def __repr__(self) -> str:
        return f"<MerkleProof chunk={self.chunk_index} depth={self.depth}>"


class MerkleTree:
    """
    Second-preimage resistant Binary Merkle Tree for container authentication.
    """
    def __init__(self, chunk_tags: List[bytes]):
        if not chunk_tags:
            raise ValueError("chunk_tags must contain at least one tag")

        for tag in chunk_tags:
            if len(tag) != CV_MERKLE_HASH_SIZE:
                raise ValueError(f"Each chunk tag must be {CV_MERKLE_HASH_SIZE} bytes")

        self._c_tree = _CMerkleTree()
        self._count = len(chunk_tags)
        raw_tags = b"".join(chunk_tags)

        rc = lib.cv_merkle_build(raw_tags, self._count, ctypes.byref(self._c_tree))
        if rc != 0:
            raise CryptoVaultException(rc, "Failed to construct Merkle tree")

        root_buf = (ctypes.c_uint8 * CV_MERKLE_HASH_SIZE)()
        lib.cv_merkle_get_root(ctypes.byref(self._c_tree), root_buf)
        self.root: bytes = bytes(root_buf)

    def __del__(self):
        if hasattr(self, "_c_tree") and self._c_tree.nodes:
            lib.cv_merkle_free(ctypes.byref(self._c_tree))

    @property
    def num_leaves(self) -> int:
        return self._count

    def generate_proof(self, chunk_index: int) -> MerkleProof:
        """
        Generate an O(log N) authentication proof for a target chunk index.
        """
        if chunk_index < 0 or chunk_index >= self._count:
            raise IndexError("chunk_index out of bounds")

        proof_c = _CMerkleProof()
        rc = lib.cv_merkle_gen_proof(ctypes.byref(self._c_tree), chunk_index, ctypes.byref(proof_c))
        if rc != 0:
            raise CryptoVaultException(rc, f"Failed to generate proof for chunk {chunk_index}")

        siblings = [bytes(proof_c.siblings[d]) for d in range(proof_c.depth)]
        return MerkleProof(chunk_index=proof_c.chunk_index, depth=proof_c.depth, siblings=siblings)

    def verify_proof(self, *args) -> bool:
        """
        Verify a chunk tag against an authentic Merkle root using its proof alone.
        Can be called as:
          tree.verify_proof(chunk_tag, proof)
        or with an explicit root:
          tree.verify_proof(expected_root, chunk_tag, proof)
        """
        if len(args) == 2:
            expected_root = self.root
            chunk_tag, proof = args
        elif len(args) == 3:
            expected_root, chunk_tag, proof = args
        else:
            raise TypeError("verify_proof expects (chunk_tag, proof) or (expected_root, chunk_tag, proof)")

        if len(expected_root) != CV_MERKLE_HASH_SIZE or len(chunk_tag) != CV_MERKLE_HASH_SIZE:
            raise ValueError("Root and tag must be 32 bytes")

        c_root = (ctypes.c_uint8 * CV_MERKLE_HASH_SIZE).from_buffer_copy(expected_root)
        c_tag = (ctypes.c_uint8 * CV_MERKLE_HASH_SIZE).from_buffer_copy(chunk_tag)

        proof_c = _CMerkleProof()
        proof_c.chunk_index = proof.chunk_index
        proof_c.depth = proof.depth
        for d, sib in enumerate(proof.siblings):
            for b in range(CV_MERKLE_HASH_SIZE):
                proof_c.siblings[d][b] = sib[b]

        rc = lib.cv_merkle_verify_proof(c_root, c_tag, ctypes.byref(proof_c))
        return rc == 0

    @staticmethod
    def verify_proof_static(expected_root: bytes, chunk_tag: bytes, proof: MerkleProof) -> bool:
        """Static verification given root, tag, and proof."""
        if len(expected_root) != CV_MERKLE_HASH_SIZE or len(chunk_tag) != CV_MERKLE_HASH_SIZE:
            raise ValueError("Root and tag must be 32 bytes")

        c_root = (ctypes.c_uint8 * CV_MERKLE_HASH_SIZE).from_buffer_copy(expected_root)
        c_tag = (ctypes.c_uint8 * CV_MERKLE_HASH_SIZE).from_buffer_copy(chunk_tag)

        proof_c = _CMerkleProof()
        proof_c.chunk_index = proof.chunk_index
        proof_c.depth = proof.depth
        for d, sib in enumerate(proof.siblings):
            for b in range(CV_MERKLE_HASH_SIZE):
                proof_c.siblings[d][b] = sib[b]

        rc = lib.cv_merkle_verify_proof(c_root, c_tag, ctypes.byref(proof_c))
        return rc == 0

    def locate_corruption(self, candidate) -> List[int]:
        """
        Detect whether candidate tags or root diverge from this tree.
        If candidate is a list of chunk tags: identifies specific leaf indices that fail verification.
        If candidate is an expected root (32 bytes): calls C-level tree divergence check.
        """
        if isinstance(candidate, list):
            corrupt = []
            for i, tag in enumerate(candidate):
                if i >= self._count or not self.verify_proof(tag, self.generate_proof(i)):
                    corrupt.append(i)
            return corrupt

        c_root = (ctypes.c_uint8 * CV_MERKLE_HASH_SIZE).from_buffer_copy(candidate)
        bad_arr = (ctypes.c_uint64 * self._count)()
        num_bad = ctypes.c_size_t(0)

        rc = lib.cv_merkle_locate_corruption(
            ctypes.byref(self._c_tree), c_root, bad_arr, self._count, ctypes.byref(num_bad)
        )
        if rc != 0:
            raise CryptoVaultException(rc, "Corruption localization failed")

        return [int(bad_arr[i]) for i in range(num_bad.value)]

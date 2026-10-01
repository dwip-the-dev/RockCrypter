"""
CryptoVault Envelope & Container Binary Inspector Module.
=========================================================

This module parses and inspects low-level binary headers and cryptographic
metadata from encrypted .cvlt and .cvpkg files without decrypting the payload.
"""

from typing import Dict, Any, Optional
import struct
import os
import ctypes
from .binding import lib, CryptoVaultException

# Header Constants
CV_MAGIC_BYTES = b"CVLTv100"
CV_PKG_MAGIC = b"CVPKG200"

class EnvelopeHeader:
    """Parsed metadata from a CryptoVault .cvlt envelope header."""

    def __init__(self, magic: bytes, version: int, cipher_suite: int, flags: int,
                 mem_cost_kb: int, time_cost: int, salt: bytes, nonce: bytes,
                 payload_len: int, aad_len: int, header_mac: bytes):
        self.magic = magic
        self.version = version
        self.cipher_suite = cipher_suite
        self.flags = flags
        self.mem_cost_kb = mem_cost_kb
        self.time_cost = time_cost
        self.salt = salt
        self.nonce = nonce
        self.payload_len = payload_len
        self.aad_len = aad_len
        self.header_mac = header_mac

    @property
    def is_streaming(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def is_base_1mib_hardened(self) -> bool:
        return self.mem_cost_kb >= 1024

    def to_dict(self) -> Dict[str, Any]:
        return {
            "magic": self.magic.decode("ascii", errors="replace"),
            "version": f"{self.version >> 8}.{self.version & 0xFF}",
            "cipher_suite": "SP-ARX-256 + 512-bit Wide Sponge (Cascaded)" if self.cipher_suite == 1 else "Unknown",
            "is_streaming": self.is_streaming,
            "mem_cost_kb": self.mem_cost_kb,
            "time_cost_passes": self.time_cost,
            "salt_hex": self.salt.hex(),
            "nonce_hex": self.nonce.hex(),
            "payload_bytes": self.payload_len,
            "aad_bytes": self.aad_len,
            "header_mac_hex": self.header_mac.hex()
        }

class EnvelopeInspector:
    """Inspector utility for analyzing encrypted files."""

    HEADER_FORMAT = "<8sHHII32s24sQI32s"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    @classmethod
    def inspect_file(cls, file_path: str) -> EnvelopeHeader:
        """
        Inspect the binary header of an encrypted .cvlt file.

        :param file_path: Path to .cvlt file.
        :return: EnvelopeHeader instance.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            raw_header = f.read(cls.HEADER_SIZE)

        if len(raw_header) < cls.HEADER_SIZE:
            raise ValueError("File is smaller than the required header size (120 bytes)")

        fields = struct.unpack(cls.HEADER_FORMAT, raw_header)
        magic = fields[0]
        if magic != CV_MAGIC_BYTES:
            raise ValueError(f"Invalid magic header: {magic!r}, expected {CV_MAGIC_BYTES!r}")

        return EnvelopeHeader(
            magic=fields[0],
            version=fields[1],
            cipher_suite=fields[2],
            flags=fields[3],
            mem_cost_kb=fields[4],
            time_cost=fields[5],
            salt=fields[6],
            nonce=fields[7],
            payload_len=fields[8],
            aad_len=fields[9],
            header_mac=fields[10]
        )

    @classmethod
    def print_analysis(cls, file_path: str) -> None:
        """Print a formatted human-readable analysis of an encrypted file."""
        hdr = cls.inspect_file(file_path)
        d = hdr.to_dict()

        print("====================================================================")
        print("               CRYPTOVAULT ENVELOPE HEADER ANALYSIS                 ")
        print("====================================================================")
        print(f"File Path:          {file_path}")
        print(f"Format Magic:       {d['magic']} (Validated)")
        print(f"Container Version:  {d['version']}")
        print(f"Cipher Suite:       {d['cipher_suite']}")
        print(f"Stream Engine:      {'1 MiB Chunked Ratchet' if d['is_streaming'] else 'Single Envelope'}")
        print(f"KDF Memory Cost:    {d['mem_cost_kb']} KiB ({d['mem_cost_kb']/1024:.2f} MiB base memory-hard)")
        print(f"KDF Time Cost:      {d['time_cost_passes']} mixing passes")
        print(f"Cryptographic Salt: {d['salt_hex']}")
        print(f"Unique Nonce:       {d['nonce_hex']}")
        print(f"Payload Size:       {d['payload_bytes']} bytes")
        print(f"AAD Metadata Size:  {d['aad_bytes']} bytes")
        print(f"Tier 1 Header MAC:  {d['header_mac_hex']}")
        print("====================================================================")

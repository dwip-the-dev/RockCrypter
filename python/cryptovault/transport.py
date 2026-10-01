"""
CryptoVault Transport & Out-of-Band Key Distribution Helper.
============================================================

This module assists users with transferring decryption keys across separate
out-of-band channels (SMS, Signal, Terminal QR codes, Paper Printouts):
1. Key bundle creation (JSON-in-Armor) for colleagues.
2. Formatted terminal instructions for secure phone / chat transmission.
3. Printable multi-party paper backup custodian sheets.
4. Out-of-band fingerprint verification for authenticating public keys.
"""

from typing import Dict, Any, List
import json
import base64
import hashlib
from .armor import AsciiArmor

class OutOfBandTransport:
    """Utilities for preparing out-of-band key exchange packages."""

    @staticmethod
    def create_key_bundle(key_bytes: bytes, filename: str,
                          notes: str = "") -> str:
        """
        Create a formatted JSON-in-Armor text bundle for sending a key to a colleague.

        :param key_bytes: Raw 32-byte symmetric key.
        :param filename: Name of the associated encrypted file.
        :param notes: Optional instructions or context note.
        :return: Copy-pasteable text block.
        """
        armored_key = AsciiArmor.encode_key(key_bytes)
        bundle = {
            "application": "CryptoVault",
            "version": "2.4.0",
            "associated_file": filename,
            "instructions": "Use this key in CryptoVault to decrypt the associated file.",
            "notes": notes,
            "armored_key": armored_key
        }
        json_str = json.dumps(bundle, indent=2)
        return (
            "------------------- CRYPTOVAULT KEY BUNDLE -------------------\n"
            f"{json_str}\n"
            "----------------- END CRYPTOVAULT KEY BUNDLE -----------------"
        )

    @staticmethod
    def parse_key_bundle(bundle_text: str) -> Dict[str, Any]:
        """
        Parse a formatted key bundle text block and extract the key.

        :param bundle_text: Raw bundle string.
        :return: Dictionary containing 'key_bytes', 'filename', and 'notes'.
        """
        # Extract JSON content
        start = bundle_text.find("{")
        end = bundle_text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("Invalid key bundle: could not locate JSON structure")

        json_part = bundle_text[start:end+1]
        data = json.loads(json_part)

        armored_key = data.get("armored_key", "")
        key_bytes = AsciiArmor.decode_key(armored_key)

        return {
            "key_bytes": key_bytes,
            "associated_file": data.get("associated_file", "unknown"),
            "notes": data.get("notes", "")
        }

    @staticmethod
    def generate_ascii_qr_instructions(key_bytes: bytes, filename: str) -> str:
        """
        Generate terminal-friendly visual instructions for out-of-band key sharing.
        """
        armored = AsciiArmor.encode_key(key_bytes)
        return (
            "\n"
            "+====================================================================+\n"
            "|           CRYPTOVAULT SECURE OUT-OF-BAND KEY TRANSMISSION          |\n"
            "+====================================================================+\n"
            f"| Target Encrypted Document:  {filename:<38} |\n"
            "| Channel Recommendation:     Signal / Matrix / Wire / In-Person     |\n"
            "| Security Rule:              NEVER send over the same channel as file|\n"
            "+--------------------------------------------------------------------+\n"
            "| Copy and send the following armored key to the recipient:          |\n"
            "+--------------------------------------------------------------------+\n\n"
            f"{armored}\n"
        )

    @staticmethod
    def generate_paper_backup_sheet(share_strings: List[str],
                                    custodian_names: List[str],
                                    title: str = "Corporate Vault Disaster Recovery") -> str:
        """
        Generate printable paper custodian backup instructions.
        """
        lines = [
            "================================================================================",
            f"          CRYPTOVAULT AIR-GAPPED PAPER BACKUP CUSTODIAN SHEET                  ",
            f"          Title: {title}                                                       ",
            "================================================================================",
            "SECURITY PROTOCOL NOTICE:",
            "- Each sheet contains an isolated mathematical share of the master vault key.",
            "- Keep this paper locked in a physical safe or tamper-evident evidence pouch.",
            "- NEVER photograph, scan, or store this key share on an unencrypted computer.",
            "--------------------------------------------------------------------------------\n"
        ]

        for i, (share, name) in enumerate(zip(share_strings, custodian_names), 1):
            lines.append(f"CUSTODIAN #{i}: {name}")
            lines.append(f"SHARE IDENTIFIER: {share}")
            lines.append("STORAGE INSTRUCTIONS: Store in an air-gapped physical vault.")
            lines.append("--------------------------------------------------------------------------------\n")

        lines.append("================================================================================")
        return "\n".join(lines)

    @staticmethod
    def verify_fingerprint(expected_fp: str, actual_fp: str) -> bool:
        """
        Constant-time string comparison for visual SHA-3 fingerprints.
        """
        exp_clean = expected_fp.strip().upper().replace(" ", "")
        act_clean = actual_fp.strip().upper().replace(" ", "")
        if len(exp_clean) != len(act_clean):
            return False
        diff = 0
        for c1, c2 in zip(exp_clean, act_clean):
            diff |= ord(c1) ^ ord(c2)
        return diff == 0

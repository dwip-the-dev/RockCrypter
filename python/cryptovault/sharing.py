"""
CryptoVault High-Level File & Key Sharing Workflow Orchestrator.
===============================================================

This module directly addresses the primary user requirement:
How to encrypt a file, safely share the encrypted file over untrusted channels,
and securely share the decryption key with the intended recipient.

Workflows Provided:
-------------------
1. Workflow A: Asymmetric Public-Key Hybrid Sharing (Recommended for Alice & Bob)
   - Alice encrypts directly for Bob using Bob's public key.
   - The encrypted package contains the encapsulated session key.
   - No separate key exchange needed! Bob decrypts directly using his private key.

2. Workflow B: Split-Channel Symmetric Sharing (Email + Secure Chat / Out-of-Band)
   - Alice encrypts the document with a fresh, random 256-bit symmetric key.
   - The encrypted file (.cvlt) is sent via Email or Cloud Drive.
   - The key is exported as an armored string (or split into Shamir shares)
     and sent over an independent secure channel (Signal, WhatsApp, SMS, or QR code).

3. Workflow C: Multi-Custodian Quorum Sharing (M-of-N Shamir Quorum)
   - Alice encrypts the document.
   - The key is split into N shares with threshold M.
   - The file is unlocked only when M custodians present their shares.
"""

from typing import List, Tuple, Optional
import os
import shutil
from .vault import CryptoKey, CryptoVault
from .hybrid import KeyPair, HybridEncryption
from .shamir import ShamirSecretSharing, KeyShare
from .armor import AsciiArmor

class SecureSharingWorkflow:
    """End-to-End file and key sharing coordinator."""

    @staticmethod
    def share_asymmetric_package(src_file: str, out_pkg_path: str,
                                 recipient_pubkey_armored: str) -> None:
        """
        Encrypt a document for a recipient using their public key.
        Generates a self-contained hybrid envelope (.cvpkg) that only the recipient
        can open with their private key.

        :param src_file: Source document path.
        :param out_pkg_path: Destination path (e.g. 'report.cvpkg').
        :param recipient_pubkey_armored: Recipient's armored public key string.
        """
        recipient_pub_bytes = AsciiArmor.decode_public_key(recipient_pubkey_armored)
        HybridEncryption.encrypt_file(src_file, out_pkg_path, recipient_pub_bytes)

    @staticmethod
    def receive_asymmetric_package(pkg_path: str, dest_file: str,
                                   recipient_privkey_bytes: bytes) -> None:
        """
        Decrypt a received hybrid envelope using the recipient's private key.

        :param pkg_path: Path to received .cvpkg / .cvlt file.
        :param dest_file: Destination path for restored document.
        :param recipient_privkey_bytes: Recipient's 32-byte private key.
        """
        HybridEncryption.decrypt_file(pkg_path, dest_file, recipient_privkey_bytes)

    @staticmethod
    def share_split_channel(src_file: str, out_enc_path: str) -> Tuple[str, str]:
        """
        Encrypt a document with a fresh 256-bit symmetric key for split-channel transmission.
        
        Returns:
            Tuple[armored_key_string, instructions_text]
        The caller sends:
            1. 'out_enc_path' via Email or Cloud Storage (Channel 1).
            2. 'armored_key_string' via Signal, SMS, or In-Person (Channel 2).
        """
        key = CryptoKey.generate()
        CryptoVault.encrypt_file(src_file, out_enc_path, key=key)

        armored_key = AsciiArmor.encode_key(key.raw_bytes)
        instructions = (
            "=================== CRYPTOVAULT SECURE KEY TRANSFER ===================\n"
            "This armored key decrypts the encrypted document you received.\n"
            "Keep this key secure and do NOT transmit it over the same communication\n"
            "channel used to send the encrypted document.\n\n"
            f"{armored_key}\n"
            "=======================================================================\n"
        )
        return armored_key, instructions

    @staticmethod
    def receive_split_channel(enc_file: str, dest_file: str, armored_key: str) -> None:
        """
        Decrypt a split-channel encrypted file using the received armored key.
        """
        key_bytes = AsciiArmor.decode_key(armored_key)
        key = CryptoKey.from_bytes(key_bytes)
        CryptoVault.decrypt_file(enc_file, dest_file, key=key)

    @staticmethod
    def share_quorum(src_file: str, out_enc_path: str,
                     threshold_k: int, total_shares_n: int) -> Tuple[List[str], str]:
        """
        Encrypt a document and split the master decryption key into N Shamir shares
        requiring any K shares to reconstruct.
        
        Returns:
            Tuple[list_of_serialized_shares, instructions_text]
        """
        key = CryptoKey.generate()
        CryptoVault.encrypt_file(src_file, out_enc_path, key=key)

        shares = ShamirSecretSharing.split(key.raw_bytes, threshold_k, total_shares_n)
        share_strings = [s.to_string() for s in shares]

        instructions = (
            f"=== CRYPTOVAULT M-OF-N QUORUM: {threshold_k}-OF-{total_shares_n} THRESHOLD ===\n"
            f"The document '{os.path.basename(src_file)}' has been encrypted.\n"
            f"Any {threshold_k} of the following {total_shares_n} shares must be presented\n"
            f"to unlock the document. Distribute one share to each trusted custodian.\n"
        )
        return share_strings, instructions

    @staticmethod
    def receive_quorum(enc_file: str, dest_file: str,
                       share_strings_subset: List[str]) -> None:
        """
        Reconstruct the master key from a quorum of shares and decrypt the document.
        """
        shares = [KeyShare.from_string(s) for s in share_strings_subset]
        recovered_key_bytes = ShamirSecretSharing.combine(shares)
        key = CryptoKey.from_bytes(recovered_key_bytes)
        CryptoVault.decrypt_file(enc_file, dest_file, key=key)

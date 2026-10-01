"""
Cryptanalysis, statistical randomness metrics, and avalanche analysis.
"""

import math
import secrets
from typing import Dict, Any
from .vault import CryptoKey, CryptoVault
from .binding import (
    _lib, CoreCtx, c_uint8, POINTER, CryptoVaultException
)

def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte (theoretical max 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy

def calculate_chisq(data: bytes) -> Dict[str, float]:
    """Calculates Chi-Square goodness-of-fit against uniform byte distribution."""
    if not data:
        return {"chisq": 0.0, "expected_per_bin": 0.0}
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    expected = len(data) / 256.0
    chisq = sum(((c - expected) ** 2) / expected for c in counts)
    return {
        "chisq": chisq,
        "degrees_of_freedom": 255,
        "expected_per_bin": expected
    }

def analyze_avalanche(samples: int = 50) -> Dict[str, Any]:
    """
    Evaluates Strict Avalanche Criterion (SAC) for the core SP-ARX cipher.
    Flips each bit of the 256-bit block and measures output bit change distribution.
    """
    key_bytes = secrets.token_bytes(32)
    c_key = (c_uint8 * 32).from_buffer_copy(key_bytes)

    ctx = CoreCtx()
    _lib.cv_core_expand_key(POINTER(CoreCtx)(ctx), c_key)

    total_flips = 0
    total_trials = samples * 256
    flip_distribution = []

    c_in1 = (c_uint8 * 32)()
    c_in2 = (c_uint8 * 32)()
    c_out1 = (c_uint8 * 32)()
    c_out2 = (c_uint8 * 32)()

    for _ in range(samples):
        pt1 = bytearray(secrets.token_bytes(32))
        for i in range(32):
            c_in1[i] = pt1[i]
        _lib.cv_core_encrypt_block(POINTER(CoreCtx)(ctx), c_in1, c_out1)
        out1_bytes = bytes(c_out1)

        for bit in range(256):
            pt2 = bytearray(pt1)
            pt2[bit // 8] ^= (1 << (bit % 8))
            for i in range(32):
                c_in2[i] = pt2[i]
            _lib.cv_core_encrypt_block(POINTER(CoreCtx)(ctx), c_in2, c_out2)
            out2_bytes = bytes(c_out2)

            flips = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(out1_bytes, out2_bytes))
            total_flips += flips
            flip_distribution.append(flips)

    _lib.cv_core_clear(POINTER(CoreCtx)(ctx))

    mean_flips = total_flips / total_trials
    mean_pct = (mean_flips / 256.0) * 100.0
    variance = sum((x - 128.0) ** 2 for x in flip_distribution) / total_trials
    std_dev = math.sqrt(variance)

    return {
        "samples": samples,
        "total_trials": total_trials,
        "mean_flips": mean_flips,
        "mean_percentage": mean_pct,
        "ideal_percentage": 50.0,
        "std_dev_bits": std_dev
    }

def simulate_tamper_suite() -> Dict[str, Any]:
    """
    Simulates deliberate tamper injections across payload, header, tag, and AAD.
    Verifies that zero unauthenticated bytes are ever released.
    """
    key = CryptoKey.generate()
    secret_text = b"Zero-Trust Academic Cryptographic Research Payload"
    aad = b"MetadataVerificationAAD"

    envelope = CryptoVault.encrypt(secret_text, key, aad=aad, mem_cost_kb=128, time_cost=1)
    results = {"total_tests": 0, "rejected": 0, "failures": 0}

    # 1. Byte flip mutations in ciphertext
    for offset in range(len(envelope)):
        tampered = bytearray(envelope)
        tampered[offset] ^= 0x01
        results["total_tests"] += 1
        try:
            CryptoVault.decrypt(bytes(tampered), key, expected_aad=aad)
            results["failures"] += 1
        except CryptoVaultException:
            results["rejected"] += 1

    # 2. AAD tampering
    results["total_tests"] += 1
    try:
        CryptoVault.decrypt(envelope, key, expected_aad=b"TamperedAAD")
        results["failures"] += 1
    except CryptoVaultException:
        results["rejected"] += 1

    # 3. Truncation
    for cut in [1, 8, 16, 32]:
        results["total_tests"] += 1
        try:
            CryptoVault.decrypt(envelope[:-cut], key, expected_aad=aad)
            results["failures"] += 1
        except CryptoVaultException:
            results["rejected"] += 1

    results["rejection_rate_pct"] = (results["rejected"] / results["total_tests"]) * 100.0
    return results

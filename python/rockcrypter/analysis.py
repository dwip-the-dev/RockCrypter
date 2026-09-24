"""
Cryptanalytic analysis, statistical testing, and avalanche metrics.
"""

import math
import secrets
from typing import Dict, Any
from .cipher import RockKey, RockCrypter
from .binding import (
    _lib, RockCoreCtx, c_uint8, POINTER, RockException
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
    Evaluates Strict Avalanche Criterion (SAC) for RockCore-256 block cipher.
    Flips each bit of the 256-bit block and measures output bit change distribution.
    """
    key_bytes = secrets.token_bytes(32)
    c_key = (c_uint8 * 32).from_buffer_copy(key_bytes)

    ctx = RockCoreCtx()
    _lib.rock_core_expand_key(POINTER(RockCoreCtx)(ctx), c_key)

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
        _lib.rock_core_encrypt_block(POINTER(RockCoreCtx)(ctx), c_in1, c_out1)
        out1_bytes = bytes(c_out1)

        for bit in range(256):
            pt2 = bytearray(pt1)
            pt2[bit // 8] ^= (1 << (bit % 8))
            for i in range(32):
                c_in2[i] = pt2[i]
            _lib.rock_core_encrypt_block(POINTER(RockCoreCtx)(ctx), c_in2, c_out2)
            out2_bytes = bytes(c_out2)

            flips = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(out1_bytes, out2_bytes))
            total_flips += flips
            flip_distribution.append(flips)

    _lib.rock_core_clear(POINTER(RockCoreCtx)(ctx))

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
    key = RockKey.generate()
    secret_text = b"Zero-Trust Cryptographic Pipeline Test"
    aad = b"MetadataVerificationAAD"

    envelope = RockCrypter.encrypt(secret_text, key, aad=aad, mem_cost_kb=128, time_cost=1)
    results = {"total_tests": 0, "rejected": 0, "failures": 0}

    # 1. Byte flip mutations in ciphertext
    for offset in range(len(envelope)):
        tampered = bytearray(envelope)
        tampered[offset] ^= 0x01
        results["total_tests"] += 1
        try:
            RockCrypter.decrypt(bytes(tampered), key, expected_aad=aad)
            results["failures"] += 1
        except RockException:
            results["rejected"] += 1

    # 2. AAD tampering
    results["total_tests"] += 1
    try:
        RockCrypter.decrypt(envelope, key, expected_aad=b"TamperedAAD")
        results["failures"] += 1
    except RockException:
        results["rejected"] += 1

    # 3. Truncation
    for cut in [1, 8, 16, 32]:
        results["total_tests"] += 1
        try:
            RockCrypter.decrypt(envelope[:-cut], key, expected_aad=aad)
            results["failures"] += 1
        except RockException:
            results["rejected"] += 1

    results["rejection_rate_pct"] = (results["rejected"] / results["total_tests"]) * 100.0
    return results

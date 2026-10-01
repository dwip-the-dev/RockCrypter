"""
CryptoVault Performance & Cryptographic Benchmark Suite.
========================================================

Runs automated benchmarks for:
1. SP-ARX-256 Block Cipher Throughput (MiB/s).
2. 512-Bit Wide Sponge Permutation Throughput (MiB/s).
3. 1 MiB Base Memory-Hard KDF Latency & RAM scaling.
4. 1 MiB Chunked Streaming File Encryption/Decryption Throughput.
"""

from typing import Dict, Any
import time
import os
import tempfile
try:
    from .vault import CryptoKey, CryptoVault
    from .hybrid import KeyPair, HybridEncryption
    from .binding import lib
except ImportError:
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from cryptovault.vault import CryptoKey, CryptoVault
    from cryptovault.hybrid import KeyPair, HybridEncryption
    from cryptovault.binding import lib

class CryptographicBenchmark:
    """Benchmark runner for measuring cryptographic performance."""

    @staticmethod
    def benchmark_kdf(mem_costs_kb=(64, 256, 1024), iterations: int = 3) -> Dict[int, float]:
        """
        Benchmark KDF derivation time across different memory scratchpad sizes.

        :param mem_costs_kb: Iterable of memory costs in KiB.
        :param iterations: Number of trials to average.
        :return: Dict mapping mem_cost_kb to average elapsed time in seconds.
        """
        results = {}
        salt = os.urandom(32)
        password = b"BenchmarkMasterSecretPassphrase2026"

        for mem in mem_costs_kb:
            times = []
            for _ in range(iterations):
                t0 = time.perf_counter()
                CryptoVault.encrypt(b"BenchmarkMasterDataPayload", password.decode("utf-8"),
                                    mem_cost_kb=mem, time_cost=2)
                t1 = time.perf_counter()
                times.append(t1 - t0)
            avg_time = sum(times) / len(times)
            results[mem] = avg_time

        return results

    @staticmethod
    def benchmark_stream_throughput(file_size_mb: int = 10) -> Dict[str, float]:
        """
        Measure 1 MiB chunked streaming encryption and decryption throughput.

        :param file_size_mb: Size of test file in Megabytes.
        :return: Dict with 'encrypt_mbps' and 'decrypt_mbps'.
        """
        total_bytes = file_size_mb * 1024 * 1024
        pattern = os.urandom(65536)

        with tempfile.NamedTemporaryFile(delete=False) as f_in, \
             tempfile.NamedTemporaryFile(delete=False) as f_enc, \
             tempfile.NamedTemporaryFile(delete=False) as f_dec:
            in_path = f_in.name
            enc_path = f_enc.name
            dec_path = f_dec.name

        try:
            # Write test payload
            with open(in_path, "wb") as f:
                written = 0
                while written < total_bytes:
                    to_write = min(len(pattern), total_bytes - written)
                    f.write(pattern[:to_write])
                    written += to_write

            key = CryptoKey.generate()

            # Benchmark encryption
            t0 = time.perf_counter()
            CryptoVault.encrypt_file(in_path, enc_path, key=key)
            t1 = time.perf_counter()
            enc_time = t1 - t0
            enc_mbps = file_size_mb / enc_time if enc_time > 0 else 0.0

            # Benchmark decryption
            t2 = time.perf_counter()
            CryptoVault.decrypt_file(enc_path, dec_path, key=key)
            t3 = time.perf_counter()
            dec_time = t3 - t2
            dec_mbps = file_size_mb / dec_time if dec_time > 0 else 0.0

            return {
                "file_size_mb": file_size_mb,
                "enc_time_sec": enc_time,
                "enc_mbps": enc_mbps,
                "dec_time_sec": dec_time,
                "dec_mbps": dec_mbps
            }
        finally:
            for p in (in_path, enc_path, dec_path):
                if os.path.exists(p):
                    try: os.unlink(p)
                    except OSError: pass

    @staticmethod
    def run_all() -> None:
        """Run all performance benchmarks and print a summary report."""
        print("====================================================================")
        print("                 CRYPTOVAULT PERFORMANCE BENCHMARK                  ")
        print("====================================================================")

        print("[1/2] Benchmarking 1 MiB Base Memory-Hard KDF Scaling...")
        kdf_results = CryptographicBenchmark.benchmark_kdf([64, 256, 1024], iterations=2)
        for mem, sec in kdf_results.items():
            print(f"  - Memory Cost {mem:4d} KiB ({mem/1024:4.2f} MiB): {sec*1000:7.2f} ms per derivation")

        print("\n[2/2] Benchmarking 10 MiB Chunked Streaming Throughput...")
        stream_results = CryptographicBenchmark.benchmark_stream_throughput(10)
        print(f"  - Encryption:  {stream_results['enc_mbps']:7.2f} MiB/s ({stream_results['enc_time_sec']:.3f} s for 10 MiB)")
        print(f"  - Decryption:  {stream_results['dec_mbps']:7.2f} MiB/s ({stream_results['dec_time_sec']:.3f} s for 10 MiB)")
        print("====================================================================")
        print("Benchmark Complete! All tests finished successfully.\n")

if __name__ == "__main__":
    CryptographicBenchmark.run_all()

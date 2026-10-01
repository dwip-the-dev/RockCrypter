"""
CryptoVault Setup & Packaging Script.
=====================================

Builds and packages the CryptoVault academic cryptographic library for Python.
Includes C shared library bindings, entry points, and metadata.
"""

from setuptools import setup, find_packages
from setuptools.command.build_py import build_py
import os
import sys
import subprocess

class BuildWithSharedLib(build_py):
    """Custom build step ensuring libcryptovault.so is compiled prior to packaging."""

    def run(self):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        so_file = os.path.join(project_root, "libcryptovault.so")

        if not os.path.exists(so_file):
            print(f"[CryptoVault Setup] Compiling shared library via Makefile in {project_root}...")
            try:
                subprocess.check_call(["make", "libcryptovault.so"], cwd=project_root)
            except Exception as e:
                print(f"[CryptoVault Setup] Warning: Makefile compilation failed: {e}")
                print("[CryptoVault Setup] Ensure gcc and make are installed on the host system.")

        super().run()

long_description = """
# CryptoVault — High-Assurance Cryptographic Storage & Transport Suite

CryptoVault is an academic capstone-grade cryptographic library designed for
high-assurance zero-trust storage and secure file transmission.

## Key Features
- **Cascaded Dual-Layer Encryption**: 32-round SP-ARX-256 block cipher coupled with 512-bit wide-state sponge duplex stream.
- **1 MiB Base Memory-Hard KDF**: 1024 KiB default locked memory matrix to resist GPU/ASIC parallel brute force.
- **1 MiB Chunked Streaming**: Constant-memory processing for multi-gigabyte datasets with ratcheted sponge chaining.
- **Asymmetric Hybrid HPKE**: Curve25519 (X25519) Montgomery scalar multiplication with NIST SP 800-38F Key Wrap.
- **Shamir's Secret Sharing**: (k, n) threshold secret sharing over GF(2^8) with 32-bit CRC verification.
- **RFC 4880 ASCII Armoring**: Radix-64 armored text blocks with 24-bit CRC error detection.
- **Self-Contained Secure Containers (.cvpkg)**: Authenticated packages with embedded metadata manifests.
"""

setup(
    name="cryptovault",
    version="2.4.0",
    description="High-Assurance Zero-Trust Cryptographic Storage & Transport Suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="CryptoVault Academic Security Group",
    author_email="security@cryptovault.academic",
    url="https://github.com/cryptovault/cryptovault",
    license="MIT",
    packages=find_packages(),
    cmdclass={
        "build_py": BuildWithSharedLib,
    },
    package_data={
        "cryptovault": ["*.so", "*.dll", "*.dylib"],
    },
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "cryptovault=cryptovault.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Education",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: C",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords=[
        "cryptography", "zero-trust", "aead", "sponge-construction",
        "curve25519", "x25519", "shamir-secret-sharing", "key-wrap",
        "ascii-armor", "memory-hard-kdf", "streaming-encryption"
    ],
    python_requires=">=3.8",
    extras_require={
        "dev": [
            "pytest>=7.0",
            "flake8>=5.0",
            "mypy>=1.0",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/cryptovault/cryptovault/issues",
        "Source": "https://github.com/cryptovault/cryptovault",
        "Documentation": "https://github.com/cryptovault/cryptovault/docs",
    },
)

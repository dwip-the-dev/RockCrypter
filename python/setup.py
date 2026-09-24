from setuptools import setup, find_packages

setup(
    name="rockcrypter",
    version="1.0.0",
    description="Experimental High-Assurance Zero-Trust Cryptographic System",
    author="RockCrypter Cryptographic Research",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "rockcrypter=rockcrypter.cli:main"
        ]
    },
    python_requires=">=3.8",
)

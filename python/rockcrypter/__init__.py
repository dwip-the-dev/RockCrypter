"""
RockCrypter — Advanced Experimental Cryptographic System
"""

from .cipher import RockKey, RockCrypter
from .binding import RockException, strerror
from .analysis import calculate_entropy, calculate_chisq, analyze_avalanche, simulate_tamper_suite

__version__ = "1.0.0"
__all__ = [
    "RockKey",
    "RockCrypter",
    "RockException",
    "strerror",
    "calculate_entropy",
    "calculate_chisq",
    "analyze_avalanche",
    "simulate_tamper_suite"
]

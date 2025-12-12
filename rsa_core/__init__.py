# rsa_core/__init__.py
"""
Modern RSA Cracking Core Module
Secure Edition 2025
"""

from .utils import mod_inverse, is_perfect_square, validate_rsa_params
from .converters import int_to_bytes, bytes_to_hex, try_decode
from .decrypt import rsa_decrypt, rsa_crt_decrypt
from .compute_d import compute_d, compute_d_from_phi
from .factorize import smart_factor_n, factor_from_factordb
from .attacks import (
    wiener_attack, 
    low_exponent_attack, 
    double_encryption_attack,
    massive_rsa_attack,
    hastad_broadcast_attack,
    even_n_attack
)

__version__ = "2025.12.1"
__author__ = "RSA Cracker Pro Team"
__all__ = [
    'mod_inverse',
    'is_perfect_square',
    'validate_rsa_params',
    'int_to_bytes',
    'bytes_to_hex',
    'try_decode',
    'rsa_decrypt',
    'rsa_crt_decrypt',
    'compute_d',
    'compute_d_from_phi',
    'smart_factor_n',
    'factor_from_factordb',
    'wiener_attack',
    'low_exponent_attack',
    'double_encryption_attack',
    'massive_rsa_attack',
    'hastad_broadcast_attack',
    'even_n_attack',
]
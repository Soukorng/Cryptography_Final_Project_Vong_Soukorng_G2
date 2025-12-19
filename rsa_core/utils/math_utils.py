"""Mathematical Utilities for RSA"""

from typing import Tuple

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm"""
    if m <= 0:
        raise ValueError("Modulus must be positive")
    
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    
    return x % m

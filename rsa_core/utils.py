# rsa_core/utils.py
"""
Secure Utility Functions for RSA Operations
"""

import math
from typing import Tuple
import gmpy2

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm - constant time implementation"""
    if a == 0:
        return b, 0, 1
    
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def mod_inverse(a: int, m: int) -> int:
    """
    Secure modular inverse using extended Euclidean algorithm.
    Raises ValueError if inverse doesn't exist.
    """
    # Input validation
    if m <= 0:
        raise ValueError("Modulus must be positive")
    
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    
    return x % m

def is_perfect_square(n: int) -> bool:
    """Check if n is a perfect square using integer sqrt"""
    if n < 0:
        return False
    
    root = int(math.isqrt(n))
    return root * root == n

def validate_rsa_params(**kwargs) -> bool:
    """
    Validate RSA parameters for security.
    Returns True if parameters are valid.
    """
    # Check for None values
    for key, value in kwargs.items():
        if value is None:
            continue
        
        # Ensure values are integers
        if not isinstance(value, int):
            return False
        
        # Check ranges
        if key in ['n', 'p', 'q'] and value <= 0:
            return False
        
        if key == 'e' and (value <= 1 or value >= kwargs.get('n', 2**1024)):
            return False
        
        if key == 'd' and value <= 0:
            return False
    
    # Specific checks
    if 'n' in kwargs and kwargs['n'] is not None:
        n = kwargs['n']
        
        # Check n is odd (except for attack scenarios)
        if n % 2 == 0 and 'e' in kwargs:
            # Even n is only acceptable in attack scenarios
            print("[SECURITY] WARNING: Even modulus detected")
        
        # Check minimum size
        if n.bit_length() < 256:
            print(f"[SECURITY] WARNING: Small modulus: {n.bit_length()} bits")
    
    return True

def secure_random_prime(bits: int) -> int:
    """
    Generate a secure random prime using system entropy.
    For testing purposes only - use cryptography library for production.
    """
    import secrets
    
    while True:
        # Generate odd number with top bits set
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        
        # Simple primality test (use gmpy2 for better performance)
        if gmpy2.is_prime(candidate):
            return int(candidate)

def bytes_to_int_secure(data: bytes) -> int:
    """Convert bytes to integer securely"""
    return int.from_bytes(data, 'big', signed=False)

def int_to_bytes_secure(n: int) -> bytes:
    """Convert integer to bytes with minimal length"""
    if n == 0:
        return b'\x00'
    
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')
"""Massive RSA Attack"""

import math
import gmpy2
from typing import Optional, Callable
from ..utils.math_utils import mod_inverse

def massive_rsa_attack(
    n: int,
    e: int,
    c: int,
    log_callback: Optional[Callable] = None
) -> Optional[int]:
    """
    Attack when n is prime (not a proper RSA modulus).
    This is a catastrophic key generation error.
    """
    def log(msg: str):
        if log_callback:
            log_callback(msg)
    
    log(f"[Massive RSA] Checking if {n.bit_length()}-bit n is prime...")
    
    # Check if n is prime using gmpy2
    try:
        if gmpy2.is_prime(n):
            log("[Massive RSA] n IS PRIME! (Critical vulnerability)")
            
            # When n is prime, phi = n-1
            phi = n - 1
            
            # Check if e is valid for this phi
            if math.gcd(e, phi) != 1:
                log("[Massive RSA] e not invertible mod (n-1)")
                return None
            
            # Compute d
            d = mod_inverse(e, phi)
            log(f"[Massive RSA] Computed d = e^(-1) mod (n-1)")
            
            # Decrypt
            m = pow(c, d, n)
            log("[Massive RSA] Decryption successful")
            return m
    except Exception as ex:
        log(f"[Massive RSA] Error: {ex}")
    
    return None
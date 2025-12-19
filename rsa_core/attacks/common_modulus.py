"""Common Modulus Attack"""

import math
from typing import Optional, Callable
from ..utils.math_utils import egcd

def common_modulus_attack(
    n: int,
    e1: int,
    e2: int,
    c1: int,
    c2: int,
    log_callback: Optional[Callable] = None
) -> Optional[int]:
    
    def log(msg: str):
        if log_callback:
            log_callback(msg)
    
    log(f"[Common Modulus] Starting attack with e1={e1}, e2={e2}")
    
    # Check if exponents are coprime
    if math.gcd(e1, e2) != 1:
        log(f"[Common Modulus] gcd(e1, e2) = {math.gcd(e1, e2)} != 1")
        return None
    
    # Use extended Euclidean algorithm
    g, a, b = egcd(e1, e2)
    
    if g != 1:
        log(f"[Common Modulus] Extended Euclidean failed: gcd = {g}")
        return None
    
    # Need to handle negative exponents
    if a < 0:
        c1_inv = pow(c1, -1, n)
        term1 = pow(c1_inv, -a, n)
    else:
        term1 = pow(c1, a, n)
    
    if b < 0:
        c2_inv = pow(c2, -1, n)
        term2 = pow(c2_inv, -b, n)
    else:
        term2 = pow(c2, b, n)
    
    m = (term1 * term2) % n
    
    log(f"[Common Modulus] ✓ Success! Recovered message")
    return m
"""Wiener's Attack"""

import gmpy2
from typing import Optional
from ..utils.validation import validate_rsa_params
from ..utils.helpers import continued_fraction, convergents

def wiener_attack(e: int, n: int) -> Optional[int]:
    """
    Wiener's attack to recover d when d is small.
    """
    if not validate_rsa_params(e=e, n=n):
        return None
    
    # Build continued fraction expansion of e/n
    cf = continued_fraction(e, n)
    convergents_list = convergents(cf)
    
    # Test each convergent
    for k, d in convergents_list:
        if k == 0:
            continue
        
        # Check if ed ≡ 1 (mod phi)
        if (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            
            # Solve quadratic: x^2 - (n - phi + 1)x + n = 0
            s = n - phi + 1
            discriminant = s * s - 4 * n
            
            if discriminant >= 0:
                sqrt_disc = gmpy2.isqrt(discriminant)
                if sqrt_disc * sqrt_disc == discriminant:
                    p = (s + sqrt_disc) // 2
                    q = (s - sqrt_disc) // 2
                    
                    if p * q == n and p > 1 and q > 1:
                        return int(d)
    
    return None
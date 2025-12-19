"""Even N Attack"""

from typing import Optional
from ..utils.math_utils import mod_inverse

def even_n_attack(n: int, e: int, c: int) -> Optional[int]:
    
    if n % 2 != 0:
        return None
    
    p = 2
    q = n // 2
    
    # Verify q is odd (should be for RSA)
    if q % 2 == 0:
        return None
    
    # Compute phi and d
    phi = (p - 1) * (q - 1)  # = q - 1
    
    try:
        d = mod_inverse(e, phi)
        m = pow(c, d, n)
        return m
    except Exception:
        return None
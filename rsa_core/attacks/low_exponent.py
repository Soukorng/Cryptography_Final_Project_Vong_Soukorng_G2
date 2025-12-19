"""Low Exponent Attack"""

import gmpy2
from typing import Optional
from ..utils.validation import validate_rsa_params

def low_exponent_attack(e: int, n: int, c: int) -> Optional[int]:
    """
    Attack when e is very small (e=3, e=5, etc.) and m^e < n.
    """
    # Input validation
    if not validate_rsa_params(e=e, n=n, c=c):
        return None
    
    if e < 3 or e > 100:  # Only for small exponents
        return None
    
    # Strategy 1: Direct root extraction
    try:
        m_root, exact = gmpy2.iroot(c, e)
        if exact:
            return int(m_root)
    except:
        pass
    
    # Strategy 2: Try c + k*n for small k (handles padding)
    for k in range(1, 1000):
        try:
            m_test, exact = gmpy2.iroot(c + k * n, e)
            if exact:
                return int(m_test)
        except:
            continue
    return None
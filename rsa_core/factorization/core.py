"""Core Factorization Algorithms"""

import math
import random
from typing import Optional

def pollard_rho(n: int) -> Optional[int]:
    """Secure Pollard Rho algorithm with iteration limits."""
    # Quick checks for small factors
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3

    def f(x: int) -> int:
        return (x * x + 1) % n

    # Multiple random seeds for better coverage
    for seed in range(5):
        try:
            x = random.randrange(2, n - 1)
            y = x
            d = 1
            iteration_limit = 100000
            
            while d == 1 and iteration_limit > 0:
                x = f(x)
                y = f(f(y))
                d = math.gcd(abs(x - y), n)
                if d == n:
                    break
                iteration_limit -= 1
                
            if 1 < d < n:
                return d
        except Exception:
            continue
    
    return None

def pollard_rho_brent(n: int) -> Optional[int]:
    """Secure Pollard Rho (Brent version) with iteration limits."""
    # Quick checks for small factors
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3

    try:
        y = random.randrange(1, n)
        c = random.randrange(1, n)
        m = random.randrange(1, n)
        
        g, r, q = 1, 1, 1
        iteration_limit = 100000

        while g == 1 and iteration_limit > 0:
            x = y
            for _ in range(r):
                y = (y * y + c) % n

            k = 0
            while k < r and g == 1 and iteration_limit > 0:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
                iteration_limit -= 1
            r <<= 1

        if g == n:
            # Retry fallback
            while iteration_limit > 0:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
                if g > 1:
                    break
                iteration_limit -= 1
        
        if 1 < g < n:
            return g
    except Exception:
        pass
    
    return None
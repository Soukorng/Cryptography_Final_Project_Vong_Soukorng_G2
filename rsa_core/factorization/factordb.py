"""FactorDB Integration"""

import socket
import gmpy2
from typing import Optional, Tuple
from factordb.factordb import FactorDB

def factor_from_factordb(n: int, timeout: int = 15) -> Tuple[Optional[int], Optional[int]]:
    """Query FactorDB for factorization"""
    try:
        # Security check: Limit bit size
        if n.bit_length() > 4096:
            return None, None
        
        f = FactorDB(n)
        try:
            # Secure timeout for network operations
            socket.setdefaulttimeout(timeout)
            f.connect()
        except Exception:
            return None, None
        
        # Get the response
        status = f.get_status()
        
        if status == "FF":  # Fully factored
            factors = f.get_factor_list()
            
            # Find prime factors
            prime_factors = []
            for factor in factors:
                if factor < 1000 or gmpy2.is_prime(factor):
                    prime_factors.append(factor)
                else:
                    # Try to break it down further
                    try:
                        sub_f = FactorDB(factor)
                        sub_f.connect()
                        if sub_f.get_status() == "FF":
                            sub_factors = sub_f.get_factor_list()
                            prime_factors.extend(sub_factors)
                    except Exception:
                        pass
            
            # We need exactly 2 factors for RSA
            if len(prime_factors) >= 2:
                # Try all combinations to find p and q
                for i in range(len(prime_factors)):
                    for j in range(i+1, len(prime_factors)):
                        if prime_factors[i] * prime_factors[j] == n:
                            p, q = sorted([prime_factors[i], prime_factors[j]])
                            return int(p), int(q)
                
                # If no pair multiplies to n, try perfect square
                for factor in prime_factors:
                    if factor * factor == n:
                        return int(factor), int(factor)
                
                # Try first factor and see if n/factor is prime
                if len(prime_factors) >= 1:
                    p = prime_factors[0]
                    q = n // p
                    if p * q == n and gmpy2.is_prime(q):
                        return int(min(p, q)), int(max(p, q))
            
        elif status == "C":  # Composite, no factors known
            pass
        elif status == "P":  # Prime
            pass
        elif status == "CF":  # Composite, partial factors
            factors = f.get_factor_list()
            if len(factors) >= 2:
                # Try to combine factors to get n
                test_n = 1
                for factor in factors:
                    test_n *= factor
                if test_n == n:
                    p, q = sorted(factors[:2])
                    return int(p), int(q)
        
    except ImportError:
        print("[FactorDB] factordb-python not installed. Run: pip install factordb-python")
    except Exception:
        pass
    
    return None, None
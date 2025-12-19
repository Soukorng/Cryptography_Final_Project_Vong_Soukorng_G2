"""Helper functions for RSA attacks"""

from typing import List, Tuple
from functools import reduce
from ..utils.math_utils import mod_inverse

def continued_fraction(e: int, n: int) -> List[int]:
    """Generate continued fraction expansion of e/n"""
    cf = []
    a, b = e, n
    while b:
        q = a // b
        cf.append(q)
        a, b = b, a % b
    return cf

def convergents(cf: List[int]) -> List[Tuple[int, int]]:
    """Generate convergents from continued fraction"""
    convergents_list = []
    h1, h2 = 1, 0
    k1, k2 = 0, 1
    
    for q in cf:
        h = q * h1 + h2
        k = q * k1 + k2
        
        if k != 0:
            convergents_list.append((h, k))
        
        h2, k2 = h1, k1
        h1, k1 = h, k
        
        if len(convergents_list) > 500:
            break
    
    return convergents_list

def chinese_remainder_theorem(remainders: List[int], moduli: List[int]) -> int:
    """
    Solve the system of congruences:
    x ≡ remainders[i] (mod moduli[i]) for all i
    """
    # Total modulus N = product of all moduli
    N = reduce(lambda a, b: a * b, moduli)
    
    # Compute solution using Garner's algorithm
    result = 0
    for i in range(len(remainders)):
        ni = moduli[i]
        Ni = N // ni
        
        # Compute modular inverse of Ni mod ni
        Mi = mod_inverse(Ni, ni)
        
        result += remainders[i] * Ni * Mi
        result %= N
    
    return result
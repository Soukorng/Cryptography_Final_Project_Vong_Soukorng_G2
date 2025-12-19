"""Decryption with Partial Key Information"""

import gmpy2
from typing import Optional, Tuple
from ..utils.math_utils import mod_inverse

def recover_prime_from_n(n: int, known_prime: int, log_callback=None) -> Optional[int]:
    """Recover other prime from n and one known prime"""
    
    def log(msg: str):
        if log_callback:
            log_callback(msg)
    
    log(f"[Recover Prime] Attempting to recover other prime from n and known prime")
    log(f"  n = {n.bit_length()}-bit")
    log(f"  known_prime = {known_prime.bit_length()}-bit")
    
    # Check if known_prime divides n
    if n % known_prime != 0:
        log(f"  ❌ known_prime ({known_prime}) does not divide n")
        return None
    
    other_prime = n // known_prime
    
    # Verify it's an integer
    if known_prime * other_prime != n:
        log(f"  ❌ {known_prime} * {other_prime} != {n}")
        return None
    
    # Check if other_prime is prime
    if not gmpy2.is_prime(other_prime):
        log(f"  ⚠️  other_prime ({other_prime}) is not prime")
        # Still return it for decryption attempts
        return other_prime
    
    log(f"  ✓ Recovered other prime = {other_prime.bit_length()}-bit")
    return other_prime

def decrypt_with_n_and_prime(
    c: int,
    n: int,
    prime: int,
    e: int = None,
    d: int = None,
    log_callback=None
) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Decrypt with modulus n and one prime"""
    
    def log(msg: str):
        if log_callback:
            log_callback(msg)
    
    log(f"[Decrypt with n+prime] Starting with n={n.bit_length()}-bit, prime={prime.bit_length()}-bit")
    
    # Step 1: Recover the other prime
    other_prime = recover_prime_from_n(n, prime, log_callback)
    if not other_prime:
        log(f"  ❌ Failed to recover other prime")
        return None, None, None
    
    # Determine which is p and which is q
    p = min(prime, other_prime)
    q = max(prime, other_prime)
    
    log(f"  • p = {p.bit_length()}-bit, q = {q.bit_length()}-bit")
    
    # Step 2: Compute phi
    phi = (p - 1) * (q - 1)
    
    # Step 3: Compute d if not provided
    if not d and e:
        try:
            d = mod_inverse(e, phi)
            log(f"  • Computed d = {d.bit_length()}-bit")
        except Exception as ex:
            log(f"  ❌ Cannot compute d: {ex}")
            return None, None, None
    elif d:
        log(f"  • Using provided d = {d.bit_length()}-bit")
    else:
        log(f"  ❌ Need either e or d to decrypt")
        return None, None, None
    
    # Step 4: Decrypt
    try:
        m = pow(c, d, n)
        log(f"  ✓ Decryption successful! Message = {m.bit_length()}-bit")
        return m, n, d
    except Exception as ex:
        log(f"  ❌ Decryption failed: {ex}")
        return None, None, None
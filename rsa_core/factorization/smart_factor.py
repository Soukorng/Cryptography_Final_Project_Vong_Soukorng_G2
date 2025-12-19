"""Smart Factorization with Multiple Algorithms"""

import math
import gmpy2
from typing import Optional, Tuple
from .core import pollard_rho, pollard_rho_brent
from .ecm import threaded_ecm
from .factordb import factor_from_factordb

def smart_factor_n(
    n: int,
    use_factordb: bool = True
) -> Tuple[Optional[int], Optional[int]]:
    """
    TURBO AUTO-FACTOR ENGINE - Extended to 4096 bits
    """
    # Security: Convert to integer and validate
    try:
        n = int(n)
    except (ValueError, TypeError):
        return None, None
    
    # Security: Basic validation
    if n <= 1:
        return None, None

    bits = n.bit_length()
    
    # STEP 1: PERFECT SQUARE CHECK
    sqrt_n = math.isqrt(n)
    if sqrt_n * sqrt_n == n:
        if gmpy2.is_prime(sqrt_n):
            return sqrt_n, sqrt_n
        return sqrt_n, sqrt_n

    # Trivial checks
    if n % 2 == 0:
        return 2, n // 2
    if n % 3 == 0:
        return 3, n // 3

    # STEP 2: Try FactorDB for ALL sizes up to 4096 bits
    if use_factordb and bits <= 4096:
        p_found, q_found = factor_from_factordb(n)
        if p_found and q_found:
            return min(p_found, q_found), max(p_found, q_found)

    # STEP 3: SMALL (< 100 bits) → Instant trial
    if bits <= 100:
        limit = min(5_000_000, math.isqrt(n) + 1)
        i = 5
        while i <= limit:
            if n % i == 0:
                return i, n // i
            if n % (i + 2) == 0:
                return i + 2, n // (i + 2)
            i += 6

    # STEP 4: MEDIUM (100–300 bits) → Pollard Rho
    if bits <= 300:
        f = pollard_rho(n)
        if f:
            return min(f, n // f), max(f, n // f)

        f = pollard_rho_brent(n)
        if f:
            return min(f, n // f), max(f, n // f)

    # STEP 5: LARGE (300–1024 bits) → Multi-threaded ECM
    if bits <= 1024:
        # Adjust parameters based on bit size
        if bits <= 512:
            B1 = 100_000
            curves_per_thread = 30
            timeout_val = 1.0
        else:
            B1 = 250_000
            curves_per_thread = 20
            timeout_val = 2.0
            
        f = threaded_ecm(n, B1=B1, threads=6, 
                         curves_per_thread=curves_per_thread, timeout=timeout_val)
        if f:
            return min(f, n // f), max(f, n // f)

    # STEP 6: VERY LARGE (1024–4096 bits) → Extended ECM
    if bits <= 4096:
        if bits <= 1536:
            B1 = 500_000
            curves_per_thread = 30
            timeout_val = 3.0
            threads = 6
        elif bits <= 3072:
            B1 = 600_000
            curves_per_thread = 20
            timeout_val = 3.0
            threads = 6
        else:
            B1 = 750_000
            curves_per_thread = 10
            timeout_val = 3.0
            threads = 4

        f = threaded_ecm(n, B1=B1, threads=threads, 
                         curves_per_thread=curves_per_thread, timeout=timeout_val)
        if f:
            return min(f, n // f), max(f, n // f)

    return None, None

def smart_factor_phi(
    phi: int,
    use_factordb: bool = True,
    log_callback=None
) -> Tuple[Optional[int], Optional[int]]:
    """
    Smart factorization of φ(n) = (p-1)(q-1) to recover p and q.
    """
    def log(msg):
        if log_callback:
            log_callback(msg)
    
    log(f"[Factor φ] Starting to factor φ = {phi.bit_length()}-bit")
    
    # First, try standard factorization
    log("[Factor φ] Attempting standard factorization...")
    f1, f2 = smart_factor_n(phi, use_factordb=use_factordb)
    
    if f1 and f2:
        log(f"[Factor φ] Found factors: f1 = {f1.bit_length()}-bit, f2 = {f2.bit_length()}-bit")
        
        # Try both orderings
        for p_minus_1, q_minus_1 in [(f1, f2), (f2, f1)]:
            p = p_minus_1 + 1
            q = q_minus_1 + 1
            
            if gmpy2.is_prime(p) and gmpy2.is_prime(q):
                if (p - 1) * (q - 1) == phi:
                    log(f"[Factor φ] ✓ Standard factorization successful!")
                    return p, q
        
        log("[Factor φ] Standard factors don't yield prime p and q")
    
    # =================== SPECIAL CASE: QUADRATIC SOLVING ===================
    log("[Factor φ] Trying quadratic solving for linear relationships...")
    
    # Common linear relationships in CTF challenges
    linear_relations = [
        (2, 1),    # p = 2q + 1 (common in safe primes)
        (2, -1),   # p = 2q - 1
        (3, 1),    # p = 3q + 1
        (3, -1),   # p = 3q - 1
        (1, 2),    # p = q + 2
        (1, -2),   # p = q - 2
        (4, 1),    # p = 4q + 1
        (4, -1),   # p = 4q - 1
    ]
    
    for a, b in linear_relations:
        for swap in [False, True]:
            if swap:
                a_eff, b_eff = a, b
            else:
                a_eff, b_eff = a, b
            
            A = a_eff
            B = b_eff - a_eff - 1
            C = -(b_eff - 1 + phi)
            
            # Discriminant
            D = B*B - 4*A*C
            
            if D < 0:
                continue
            
            # Check if D is a perfect square
            sqrt_D = gmpy2.isqrt(D)
            if sqrt_D * sqrt_D != D:
                continue
            
            # Try both roots
            for sign in [1, -1]:
                numerator = -B + sign * sqrt_D
                if numerator <= 0:
                    continue
                
                if numerator % (2*A) != 0:
                    continue
                
                q_candidate = numerator // (2*A)
                
                if swap:
                    p_candidate = q_candidate
                    q_candidate = a_eff * p_candidate + b_eff
                else:
                    p_candidate = a_eff * q_candidate + b_eff
                
                # Ensure positivity
                if p_candidate <= 0 or q_candidate <= 0:
                    continue
                
                # Check if both are prime
                if gmpy2.is_prime(p_candidate) and gmpy2.is_prime(q_candidate):
                    # Verify φ
                    if (p_candidate - 1) * (q_candidate - 1) == phi:
                        log(f"[Factor φ] ✓ Found with relation p = {a}*q + {b}" + (" (swapped)" if swap else ""))
                        log(f"[Factor φ] p = {p_candidate.bit_length()}-bit, q = {q_candidate.bit_length()}-bit")
                        return p_candidate, q_candidate
    
    # =================== GENERAL QUADRATIC SOLVING ===================
    log("[Factor φ] Trying general quadratic solving...")
    
    sqrt_phi = gmpy2.isqrt(phi)
    s_min = 2 * sqrt_phi - 1000
    s_max = 2 * sqrt_phi + 1000
    
    log(f"[Factor φ] Searching for s in range [{s_min}, {s_max}]")
    
    for s in range(s_min, s_max + 1):
        if s <= 0:
            continue
        
        # Compute discriminant
        disc = s*s - 4*s - 4*phi + 4
        
        if disc < 0:
            continue
        
        # Check if perfect square
        sqrt_disc = gmpy2.isqrt(disc)
        if sqrt_disc * sqrt_disc != disc:
            continue
        
        # Found valid s
        p_candidate = (s + sqrt_disc) // 2
        q_candidate = (s - sqrt_disc) // 2
        
        # Check if they're prime and φ matches
        if (p_candidate * q_candidate - p_candidate - q_candidate + 1) == phi:
            if gmpy2.is_prime(p_candidate) and gmpy2.is_prime(q_candidate):
                log(f"[Factor φ] ✓ Found via general quadratic!")
                log(f"[Factor φ] p = {p_candidate.bit_length()}-bit, q = {q_candidate.bit_length()}-bit")
                return p_candidate, q_candidate
    
    log("[Factor φ] ❌ All methods failed to factor φ")
    return None, None
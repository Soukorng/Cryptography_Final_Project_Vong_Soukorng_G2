import math
import random
import gmpy2
import threading
import time
import socket
from typing import Optional, Tuple
from factordb.factordb import FactorDB

# Secure precision setting
gmpy2.get_context().precision = 4096

# ==========================================================
#                 SECURE FACTORDB INTEGRATION
# ==========================================================
def factor_from_factordb(n: int, timeout: int = 15) -> Tuple[Optional[int], Optional[int]]:

    try:
        # Security check: Limit bit size
        if n.bit_length() > 4096:
            print(f"[FactorDB Security] Refusing to query {n.bit_length()}-bit number (max 4096 bits)")
            return None, None
        
        print(f"[FactorDB] Querying for {n.bit_length()}-bit n...")
        
        f = FactorDB(n)
        try:
            # Secure timeout for network operations
            socket.setdefaulttimeout(timeout)
            f.connect()
        except Exception as e:
            print(f"[FactorDB] Connection error: {e}")
            return None, None
        
        # Get the response
        status = f.get_status()
        
        if status == "FF":  # Fully factored
            factors = f.get_factor_list()
            print(f"[FactorDB] Found {len(factors)} factors")
            
            # Find prime factors with security checks
            prime_factors = []
            for factor in factors:
                # Secure prime check using gmpy2
                if factor < 1000 or gmpy2.is_prime(factor):
                    prime_factors.append(factor)
                else:
                    # Try to break it down further with error handling
                    try:
                        sub_f = FactorDB(factor)
                        sub_f.connect()
                        if sub_f.get_status() == "FF":
                            sub_factors = sub_f.get_factor_list()
                            prime_factors.extend(sub_factors)
                    except Exception:
                        pass  # Silently continue if sub-factorization fails
            
            # We need exactly 2 factors for RSA, but handle perfect squares securely
            if len(prime_factors) >= 2:
                # Try all combinations to find p and q
                for i in range(len(prime_factors)):
                    for j in range(i+1, len(prime_factors)):
                        if prime_factors[i] * prime_factors[j] == n:
                            p, q = sorted([prime_factors[i], prime_factors[j]])
                            return int(p), int(q)
                
                # If no pair multiplies to n, try to see if it's a perfect square
                for factor in prime_factors:
                    if factor * factor == n:
                        return int(factor), int(factor)
                
                # Try first factor and see if n/factor is prime
                if len(prime_factors) >= 1:
                    p = prime_factors[0]
                    q = n // p
                    if p * q == n and gmpy2.is_prime(q):
                        return int(min(p, q)), int(max(p, q))
            
            elif len(prime_factors) == 1:
                p = prime_factors[0]
                # Check if n is a perfect square of this prime
                if p * p == n:
                    return int(p), int(p)
                # Check if other factor is prime
                q = n // p
                if p * q == n and gmpy2.is_prime(q):
                    return int(min(p, q)), int(max(p, q))
        
        elif status == "C":  # Composite, no factors known
            print("[FactorDB] Composite, no factors known")
        elif status == "P":  # Prime
            print("[FactorDB] Number is prime (not RSA modulus)")
        elif status == "CF":  # Composite, partial factors
            print("[FactorDB] Partially factored")
            # Try to get what we have
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
    except Exception as e:
        print(f"[FactorDB] Error: {e}")
    
    return None, None

# ==========================================================
#                 SECURE POLLARD RHO (Classic)
# ==========================================================
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
            iteration_limit = 100000  # Security: Prevent infinite loops
            
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
            continue  # Continue with next seed if error occurs
    
    return None

# ==========================================================
#                SECURE POLLARD RHO (Brent Version)
# ==========================================================
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
        iteration_limit = 100000  # Security: Prevent infinite loops

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

# ==========================================================
#             SECURE MULTI-THREADED ECM
# ==========================================================
ECM_FOUND = None
ECM_LOCK = threading.Lock()  # Security: Thread safety

def _ecm_thread(n: int, B1: int, curves: int = 50):
    """Secure ECM worker thread with error handling."""
    global ECM_FOUND
    
    for _ in range(curves):
        with ECM_LOCK:
            if ECM_FOUND:
                return
        
        try:
            # Use gmpy2's ECM with error handling
            f = int(gmpy2.ecm(n, B1=B1))
            if 1 < f < n:
                with ECM_LOCK:
                    ECM_FOUND = f
                return
        except Exception:
            continue  # Silently continue on errors

def threaded_ecm(n: int, B1: int = 50000, threads: int = 4, 
                 curves_per_thread: int = 20, timeout: float = 2.0) -> Optional[int]:
    """
    Safe ECM — capped work, multi-threaded, with timeout.
    Never freezes GUI.
    """
    global ECM_FOUND
    ECM_FOUND = None

    # Security: Validate input parameters
    if n <= 1 or threads <= 0 or curves_per_thread <= 0:
        return None
    
    t_list = []
    for _ in range(min(threads, 8)):  # Security: Cap maximum threads
        t = threading.Thread(target=_ecm_thread, args=(n, B1, curves_per_thread))
        t.daemon = True
        t.start()
        t_list.append(t)

    # Wait with timeout to prevent hanging
    start_time = time.time()
    while time.time() - start_time < timeout:
        if ECM_FOUND:
            break
        time.sleep(0.1)

    # Clean up threads
    for t in t_list:
        t.join(timeout=0.1)

    return ECM_FOUND

# ==========================================================
#        SECURE UNIVERSAL FACTORIZER (UP TO 4096 BITS)
# ==========================================================
def smart_factor_n(n: int, use_factordb: bool = True) -> Tuple[Optional[int], Optional[int]]:
    """
    TURBO AUTO-FACTOR ENGINE - Extended to 4096 bits (Secure Edition)
    -----------------------------------------------------
    Uses:
        • FactorDB (online database) if enabled
        • Perfect square detection
        • Trial division (small)
        • Pollard Rho (up to ~300 bits)
        • Pollard Rho Brent (up to ~300 bits)
        • Multi-threaded ECM (up to ~1024 bits)
        • Auto bit-size selection with extended limits
    """
    # Security: Convert to integer and validate
    try:
        n = int(n)
    except (ValueError, TypeError):
        print("[Security] Invalid input for n")
        return None, None
    
    # Security: Basic validation
    if n <= 1:
        return None, None

    bits = n.bit_length()
    print(f"[Factor] Factoring {bits}-bit number...")

    # ==================================================
    # STEP 0: PERFECT SQUARE CHECK (for n = p^2)
    # ==================================================
    sqrt_n = math.isqrt(n)
    if sqrt_n * sqrt_n == n:
        print(f"[Factor] Perfect square detected: n = {sqrt_n}^2")
        # Check if sqrt_n is prime (likely for RSA challenges)
        try:
            if gmpy2.is_prime(sqrt_n):
                print(f"[Factor] Square root is prime, returning p = q = {sqrt_n}")
                return sqrt_n, sqrt_n
        except Exception:
            pass
        # sqrt_n might be composite, but we return it anyway
        print(f"[Factor] Returning square root as both factors")
        return sqrt_n, sqrt_n

    # -------- trivial checks ----------
    if n % 2 == 0:
        return 2, n // 2
    if n % 3 == 0:
        return 3, n // 3

    # ==================================================
    # STEP 1: Try FactorDB for ALL sizes up to 4096 bits
    # ==================================================
    if use_factordb and bits <= 4096:  # Security: Limit FactorDB queries
        print(f"[Factor] Querying FactorDB (factordb.com) for {bits}-bit n...")
        p_found, q_found = factor_from_factordb(n)
        if p_found and q_found:
            print(f"[Factor] FactorDB SUCCESS! Found factors")
            return min(p_found, q_found), max(p_found, q_found)

    # ==================================================
    # SMALL (< 100 bits) → Instant trial
    # ==================================================
    if bits <= 100:
        # Security: Limit trial division for performance
        limit = min(5_000_000, math.isqrt(n) + 1)
        i = 5
        while i <= limit:
            if n % i == 0:
                return i, n // i
            if n % (i + 2) == 0:
                return i + 2, n // (i + 2)
            i += 6

    # ==================================================
    # MEDIUM (100–300 bits) → Pollard Rho
    # ==================================================
    if bits <= 300:
        print("[Factor] Trying Pollard Rho...")
        f = pollard_rho(n)
        if f:
            print(f"[Factor] Pollard Rho found factor: {f}")
            return min(f, n // f), max(f, n // f)

        print("[Factor] Trying Pollard Rho (Brent)...")
        f = pollard_rho_brent(n)
        if f:
            print(f"[Factor] Pollard Rho Brent found factor: {f}")
            return min(f, n // f), max(f, n // f)

    # ==================================================
    # LARGE (300–1024 bits) → Multi-threaded ECM
    # ==================================================
    if bits <= 1024:
        print("[Factor] Trying ECM...")
        
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
            print(f"[Factor] ECM found factor: {f}")
            return min(f, n // f), max(f, n // f)

    # ==================================================
    # VERY LARGE (1024–4096 bits) → Extended ECM (best-effort)
    # ==================================================
    if bits <= 4096:
        print("[Factor] Trying extended ECM for very large number (best-effort, time-limited)...")
        
        # Use more conservative parameters for GUI safety
        # The bigger the number, the longer it may take; we cap time per thread.
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
            # 3073-4096 bits: best-effort, but very unlikely to succeed in reasonable time
            B1 = 750_000
            curves_per_thread = 10
            timeout_val = 3.0
            threads = 4

        f = threaded_ecm(n, B1=B1, threads=threads, 
                         curves_per_thread=curves_per_thread, timeout=timeout_val)
        if f:
            print(f"[Factor] Extended ECM found factor: {f}")
            return min(f, n // f), max(f, n // f)

    # ==================================================
    # HUGE (> 4096 bits) → Stop early
    # ==================================================
    print(f"[Factor] Number too large ({bits} bits) for efficient factoring in this tool (max 4096 bits).")
    return None, None

def smart_factor_phi(phi: int, use_factordb: bool = True, log_callback=None) -> Tuple[Optional[int], Optional[int]]:
    """
    Smart factorization of φ(n) = (p-1)(q-1) to recover p and q.
    Now includes quadratic solving for special cases like p = a*q + b.
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
    # Try to solve for p and q when they have a linear relationship: p = a*q + b
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
        # Try both directions: p = a*q + b and q = a*p + b
        for swap in [False, True]:
            if swap:
                # Swap the relationship: q = a*p + b
                a_eff, b_eff = a, b
                # We'll solve for p first
            else:
                # Original: p = a*q + b
                a_eff, b_eff = a, b
                # We'll solve for q first
            
            # Equation: φ = (p-1)(q-1)
            # With p = a*q + b: φ = (a*q + b - 1)(q - 1) = a*q² + (b - a - 1)q - (b - 1)
            # So: a*q² + (b - a - 1)q - (b - 1 + φ) = 0
            
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
                    # We solved for p actually
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
    # Try to solve the general quadratic without assuming a relationship
    log("[Factor φ] Trying general quadratic solving...")
    
    # We know: φ = (p-1)(q-1) = pq - p - q + 1
    # Let s = p + q, then φ = n - s + 1, so s = n - φ + 1
    # But we don't know n = pq
    
    # However, we can consider that p and q are roots of: x² - s*x + n = 0
    # And s² - 4n = (p-q)²
    
    # From φ = (p-1)(q-1), we have φ = pq - (p+q) + 1
    # Let n = pq, s = p+q
    # Then φ = n - s + 1 => n = φ + s - 1
    
    # Also, s² - 4n = s² - 4(φ + s - 1) = s² - 4s - 4φ + 4
    
    # For p and q to be integers, (p-q)² must be a perfect square
    # So we need s such that s² - 4s - 4φ + 4 is a perfect square
    
    # Since s ≈ 2√n and n ≈ φ, s ≈ 2√φ
    # Try s around 2√φ
    
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
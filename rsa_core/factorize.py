# rsa_core/factorize.py (TURBO 2025 EDITION - Extended to 2000 bits)
import math
import random
import gmpy2
import threading
import time

gmpy2.get_context().precision = 4096

# ==========================================================
#                 FACTORDB ONLINE INTEGRATION
# ==========================================================
def factor_from_factordb(n: int, timeout=15):
    """
    Query factordb.com for factors of n.
    Returns (p, q) if successful, (None, None) otherwise.
    """
    try:
        from factordb.factordb import FactorDB
        
        if n < 1000:
            return None, None  # Too small, use local methods
        
        print(f"[FactorDB] Querying for {n.bit_length()}-bit n...")
        
        f = FactorDB(n)
        try:
            # Try to get status with timeout
            import requests
            import socket
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
            
            # Find prime factors
            prime_factors = []
            for factor in factors:
                # Check if factor is prime (simple probabilistic check)
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
                    except:
                        pass
            
            # We need exactly 2 factors for RSA, but handle perfect squares
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
                    if gmpy2.is_prime(q):
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
#                 POLLARD RHO  (Classic)
# ==========================================================
def pollard_rho(n):
    if n % 2 == 0: return 2
    if n % 3 == 0: return 3

    def f(x): return (x * x + 1) % n

    for seed in range(5):  # multiple seeds
        x = random.randrange(2, n - 1)
        y = x
        d = 1
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)
            if d == n: break
        if 1 < d < n:
            return d
    return None

# ==========================================================
#                POLLARD RHO (Brent Version)
# ==========================================================
def pollard_rho_brent(n):
    if n % 2 == 0: return 2
    if n % 3 == 0: return 3

    y, c, m = random.randrange(1, n), random.randrange(1, n), random.randrange(1, n)
    g, r, q = 1, 1, 1

    while g == 1:
        x = y
        for _ in range(r):
            y = (y * y + c) % n

        k = 0
        while k < r and g == 1:
            ys = y
            for _ in range(min(m, r - k)):
                y = (y * y + c) % n
                q = q * abs(x - y) % n
            g = math.gcd(q, n)
            k += m
        r <<= 1

    if g == n:
        # retry fallback
        while True:
            ys = (ys * ys + c) % n
            g = math.gcd(abs(x - ys), n)
            if g > 1:
                break
    return g

# ==========================================================
#             MULTI-THREAD ECM (MAX SAFETY)
# ==========================================================
ECM_FOUND = None

def _ecm_thread(n, B1, curves=50):
    global ECM_FOUND
    for _ in range(curves):
        if ECM_FOUND: 
            return
        try:
            f = int(gmpy2.ecm(n, B1=B1))
            if 1 < f < n:
                ECM_FOUND = f
                return
        except:
            pass

def threaded_ecm(n, B1=50_000, threads=4, curves_per_thread=20, timeout=2.0):
    """
    Safe ECM — capped work, multi-threaded.
    Never freezes GUI.
    """
    global ECM_FOUND
    ECM_FOUND = None

    t_list = []
    for _ in range(threads):
        t = threading.Thread(target=_ecm_thread, args=(n, B1, curves_per_thread))
        t.daemon = True
        t.start()
        t_list.append(t)

    for t in t_list:
        t.join(timeout)  # join with timeout, never block fully

    return ECM_FOUND

# ==========================================================
#              MAIN UNIVERSAL FACTORIZER (UP TO 2048 BITS)
# ==========================================================
def smart_factor_n(n: int, use_factordb=True):
    """
    TURBO AUTO-FACTOR ENGINE - Extended to 2048 bits
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
    n = int(n)
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
        except:
            pass
        # sqrt_n might be composite, but we return it anyway
        print(f"[Factor] Returning square root as both factors")
        return sqrt_n, sqrt_n

    # -------- trivial ----------
    if n % 2 == 0: return 2, n // 2
    if n % 3 == 0: return 3, n // 3

    # ==================================================
    # STEP 1: Try FactorDB for ALL sizes up to 2000 bits
    # ==================================================
    if use_factordb:
        print(f"[Factor] Querying FactorDB (factordb.com) for {bits}-bit n...")
        p_found, q_found = factor_from_factordb(n)
        if p_found and q_found:
            print(f"[Factor] FactorDB SUCCESS! Found factors", "green")
            return min(p_found, q_found), max(p_found, q_found)

    # ==================================================
    # SMALL (< 100 bits) → Instant trial
    # ==================================================
    if bits <= 100:
        limit = min(5_000_000, math.isqrt(n) + 1)
        i = 5
        while i <= limit:
            if n % i == 0: return i, n // i
            if n % (i + 2) == 0: return i + 2, n // (i + 2)
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
            timeout = 1.0
        else:
            B1 = 250_000
            curves_per_thread = 20
            timeout = 2.0
            
        f = threaded_ecm(n, B1=B1, threads=6, curves_per_thread=curves_per_thread, timeout=timeout)
        if f:
            print(f"[Factor] ECM found factor: {f}")
            return min(f, n // f), max(f, n // f)

    # ==================================================
    # VERY LARGE (1024–2048 bits) → Extended ECM
    # ==================================================
    if bits <= 2048:
        print("[Factor] Trying extended ECM for large number...")
        
        # Use more aggressive parameters for larger numbers
        B1 = 500_000
        curves_per_thread = 15
        timeout = 3.0
        
        f = threaded_ecm(n, B1=B1, threads=4, curves_per_thread=curves_per_thread, timeout=timeout)
        if f:
            print(f"[Factor] Extended ECM found factor: {f}")
            return min(f, n // f), max(f, n // f)

    # ==================================================
    # HUGE (> 2048 bits) → Stop early
    # ==================================================
    print(f"[Factor] Number too large ({bits} bits) for efficient factoring")
    return None, None
# rsa_core/attacks.py
"""
Modern RSA Attack Implementations
Includes security enhancements and new attacks
"""

import math
from typing import Optional, Tuple, List, Callable
import gmpy2
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from .utils import mod_inverse, validate_rsa_params, chinese_remainder_theorem

def low_exponent_attack(e: int, n: int, c: int) -> Optional[int]:
    """
    Attack when e is very small (e=3, e=5, etc.) and m^e < n.
    Enhanced with multiple recovery strategies[citation:5].
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
    
    # Strategy 3: Chinese Remainder Theorem for multiple ciphertexts
    return None

def wiener_attack(e: int, n: int) -> Optional[int]:
    """
    Wiener's attack to recover d when d is small.
    Enhanced with better continued fraction handling[citation:7].
    """
    if not validate_rsa_params(e=e, n=n):
        return None
    
    # Build continued fraction expansion of e/n
    cf = []
    a, b = e, n
    while b:
        q = a // b
        cf.append(q)
        a, b = b, a % b
    
    # Generate convergents
    convergents = []
    h1, h2 = 1, 0
    k1, k2 = 0, 1
    
    for q in cf:
        h = q * h1 + h2
        k = q * k1 + k2
        
        # Skip trivial cases
        if k != 0:
            convergents.append((h, k))
        
        # Update for next iteration
        h2, k2 = h1, k1
        h1, k1 = h, k
        
        # Early termination if we have enough convergents
        if len(convergents) > 100:
            break
    
    # Test each convergent
    for k, d in convergents:
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

def hastad_broadcast_attack(e: int, 
                           ciphertexts: List[int], 
                           moduli: List[int] = None,
                           log_callback: Optional[Callable] = None) -> Optional[int]:
    """
    Håstad's Broadcast Attack for same message encrypted under multiple keys.
    
    Requirements:
    1. Same message m encrypted under different moduli n_i
    2. Same small public exponent e (e=3, e=5, etc.)
    3. At least e ciphertexts/moduli pairs
    
    Enhanced with better CRT and error handling.
    """
    def log(msg: str):
        if log_callback:
            log_callback(msg)
    
    log(f"[Håstad] Starting broadcast attack with e={e}")
    
    # If moduli not provided, assume all use same n (from single modulus scenario)
    if moduli is None:
        log(f"[Håstad] No moduli provided, using single modulus scenario")
        # Try low exponent attack instead
        return None
    
    # Validate inputs
    if len(ciphertexts) < e:
        log(f"[Håstad] Need at least {e} ciphertexts for e={e}, got {len(ciphertexts)}")
        return None
    
    if len(moduli) < e:
        log(f"[Håstad] Need at least {e} moduli for e={e}, got {len(moduli)}")
        return None
    
    # Use the minimum of available ciphertexts and moduli
    count = min(len(ciphertexts), len(moduli), e)
    log(f"[Håstad] Using {count} ciphertext-moduli pairs")
    
    # Collect the pairs to use
    c_list = ciphertexts[:count]
    n_list = moduli[:count]
    
    # Log the pairs
    for i, (ci, ni) in enumerate(zip(c_list, n_list)):
        log(f"[Håstad] Pair {i+1}: c={ci}, n={ni.bit_length()}-bits")
    
    try:
        # Step 1: Use Chinese Remainder Theorem to recover m^e
        log(f"[Håstad] Applying Chinese Remainder Theorem...")
        
        # Import CRT implementation
        from functools import reduce
        
        def chinese_remainder_theorem(remainders, moduli):
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
                try:
                    Mi = mod_inverse(Ni, ni)
                except ValueError:
                    log(f"[Håstad] Error: No inverse for {Ni} mod {ni}")
                    return None
                
                result += remainders[i] * Ni * Mi
                result %= N
            
            return result
        
        # Combine ciphertexts using CRT
        m_pow_e = chinese_remainder_theorem(c_list, n_list)
        
        if m_pow_e is None:
            log("[Håstad] CRT failed")
            return None
        
        log(f"[Håstad] Recovered m^{e} = {m_pow_e}")
        log(f"[Håstad] m^{e} is {m_pow_e.bit_length()}-bits")
        
        # Step 2: Take the e-th root over integers
        log(f"[Håstad] Computing {e}-th root...")
        
        # Check if m^e is reasonable size (should be less than product of moduli)
        max_possible_m = reduce(lambda a, b: a * b, n_list)
        if m_pow_e >= max_possible_m:
            log(f"[Håstad] Warning: m^{e} >= product of moduli, may not be correct")
        
        try:
            # Use gmpy2 for efficient root computation
            m, exact = gmpy2.iroot(m_pow_e, e)
            
            if exact:
                log(f"[Håstad] ✅ Success! Found exact {e}-th root")
                return int(m)
            else:
                log(f"[Håstad] Not an exact {e}-th root")
                
                # Try nearby values (in case of padding)
                log(f"[Håstad] Trying nearby values (for potential padding)...")
                for offset in [0, 1, -1, 2, -2]:
                    m_test, exact_test = gmpy2.iroot(m_pow_e + offset, e)
                    if exact_test:
                        log(f"[Håstad] ✅ Found exact root with offset {offset}")
                        return int(m_test)
        
        except Exception as root_ex:
            log(f"[Håstad] Error computing root: {root_ex}")
            return None
    
    except Exception as ex:
        log(f"[Håstad] Error in broadcast attack: {ex}")
        return None
    
    return None

def even_n_attack(n: int, e: int, c: int) -> Optional[int]:
    """
    Attack when N is even (catastrophic vulnerability)[citation:1][citation:6].
    One prime factor must be 2.
    """
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
    except:
        return None

def massive_rsa_attack(n: int, e: int, c: int, 
                      log_callback: Optional[Callable] = None) -> Optional[int]:
    """
    Attack when n is prime (not a proper RSA modulus)[citation:1].
    This is a catastrophic key generation error.
    """
    def log(msg: str):
        if log_callback:
            log_callback(msg)
    
    log(f"[Massive RSA] Checking if {n.bit_length()}-bit n is prime...")
    
    # Check if n is prime using gmpy2
    try:
        if gmpy2.is_prime(n):
            log("[Massive RSA] n IS PRIME! (Critical vulnerability)")
            
            # When n is prime, phi = n-1
            phi = n - 1
            
            # Check if e is valid for this phi
            if math.gcd(e, phi) != 1:
                log("[Massive RSA] e not invertible mod (n-1)")
                return None
            
            # Compute d
            d = mod_inverse(e, phi)
            log(f"[Massive RSA] Computed d = e^(-1) mod (n-1)")
            
            # Decrypt
            m = pow(c, d, n)
            log("[Massive RSA] Decryption successful")
            return m
    except Exception as ex:
        log(f"[Massive RSA] Error: {ex}")
    
    return None

def double_encryption_attack(n: int, e1: int, e2: int, c: int, log_callback=None):
    """
    Attack double encryption with identical N: c = (m^e1)^e2 mod n = m^(e1*e2) mod n
    
    Multiple strategies:
    1. Direct Wiener attack on e_total = e1 * e2 (main attack for identical N)
    2. Layered Wiener attack (if one exponent is huge)
    3. Individual Wiener attacks
    4. Factorization
    
    Returns m if successful, None otherwise.
    """
    # Helper function for logging
    def log(msg):
        if log_callback:
            log_callback(msg)
    
    log(f"[Double Encryption] Starting attack with identical n={n.bit_length()}-bit, e1={e1}, e2={e2}")
    log(f"[Double Encryption] e1 bits: {e1.bit_length()}, e2 bits: {e2.bit_length()}")
    
    # =============================================
    # STRATEGY 1: DIRECT WIENER ATTACK ON e_total (from BackdoorCTF20217)
    # =============================================
    log(f"[Double Encryption] Strategy 1: Direct Wiener attack on e_total = e1 * e2")
    e_total = e1 * e2
    log(f"[Double Encryption] e_total = e1 * e2 = {e_total}")
    log(f"[Double Encryption] e_total bit length: {e_total.bit_length()} bits")
    log(f"[Double Encryption] n bit length: {n.bit_length()} bits")
    
    # Check if e_total is suitable for Wiener attack
    # Wiener attack works best when d < n^0.25 / 3
    # Since e_total might be large, the continued fraction of e_total/n might have d in early convergents
    log(f"[Double Encryption] Trying Wiener attack on e_total...")
    d_total = wiener_attack(e_total, n)
    
    if d_total:
        log(f"[Double Encryption] ✅ WIENER ATTACK SUCCESSFUL! Found d_total = {d_total}")
        log(f"[Double Encryption] d_total bit length: {d_total.bit_length()} bits")
        
        # Decrypt directly: m = c^d_total mod n
        m = pow(c, d_total, n)
        log(f"[Double Encryption] Direct decryption successful!")
        return m
    
    log(f"[Double Encryption] Direct Wiener attack on e_total failed")
    
    # =============================================
    # STRATEGY 2: ALTERNATIVE - Try continued fractions manually (like in BackdoorCTF20217)
    # =============================================
    log(f"[Double Encryption] Strategy 2: Alternative Wiener via continued fractions")
    
    # This implements the exact method from the BackdoorCTF20217 writeup
    def continued_fraction(e, n):
        """Generate continued fraction expansion of e/n"""
        cf = []
        a, b = e, n
        while b:
            q = a // b
            cf.append(q)
            a, b = b, a % b
        return cf
    
    def convergents(cf):
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
            
            # Limit to first 100 convergents (like in Wiener attack)
            if len(convergents_list) > 500:
                break
        
        return convergents_list
    
    # Generate continued fraction of e_total/n
    cf = continued_fraction(e_total, n)
    convergents_list = convergents(cf)
    
    log(f"[Double Encryption] Generated {len(convergents_list)} convergents")
    
    # Test each convergent (k, d)
    for i, (k, d) in enumerate(convergents_list):
        if k == 0:
            continue
        
        # Check if (e_total * d - 1) is divisible by k
        if (e_total * d - 1) % k == 0:
            phi = (e_total * d - 1) // k
            
            # Check if this gives valid p and q
            s = n - phi + 1
            discriminant = s * s - 4 * n
            
            if discriminant >= 0:
                try:
                    sqrt_disc = gmpy2.isqrt(discriminant)
                    if sqrt_disc * sqrt_disc == discriminant:
                        p = (s + sqrt_disc) // 2
                        q = (s - sqrt_disc) // 2
                        
                        if p * q == n and p > 1 and q > 1:
                            log(f"[Double Encryption] ✅ Found valid d from convergent {i}: d = {d}")
                            log(f"[Double Encryption] k = {k}, phi = {phi}")
                            log(f"[Double Encryption] p = {p.bit_length()}-bit, q = {q.bit_length()}-bit")
                            
                            # Decrypt
                            m = pow(c, d, n)
                            log(f"[Double Encryption] Decryption successful via alternative method!")
                            return m
                except:
                    continue
    
    # =============================================
    # STRATEGY 3: LAYERED APPROACH (if one exponent is huge)
    # =============================================
    log(f"[Double Encryption] Strategy 3: Layered Wiener attack")
    
    # Check which exponent is larger
    if e1.bit_length() > e2.bit_length():
        huge_exp, huge_label = e1, "e1"
        small_exp, small_label = e2, "e2"
    else:
        huge_exp, huge_label = e2, "e2"
        small_exp, small_label = e1, "e1"
    
    log(f"[Double Encryption] {huge_label} is larger ({huge_exp.bit_length()} bits)")
    
    # Try Wiener on the larger exponent
    d_huge = wiener_attack(huge_exp, n)
    
    if d_huge:
        log(f"[Double Encryption] Found d for {huge_label} = {d_huge}")
        
        # Decrypt one layer
        intermediate = pow(c, d_huge, n)
        log(f"[Double Encryption] Decrypted first layer: intermediate = m^{small_exp} mod n")
        
        # Now attack the small exponent
        # Try Wiener on small exponent
        d_small = wiener_attack(small_exp, n)
        if d_small:
            log(f"[Double Encryption] Found d for {small_label} = {d_small}")
            m = pow(intermediate, d_small, n)
            log(f"[Double Encryption] Layered decryption successful!")
            return m
        
        # Try low exponent attack on small exponent
        log(f"[Double Encryption] Trying low exponent attack on {small_label}...")
        m_low = low_exponent_attack(small_exp, n, intermediate)
        if m_low:
            log(f"[Double Encryption] Low exponent attack successful!")
            return m
    
    # =============================================
    # STRATEGY 4: Try Wiener on each exponent individually
    # =============================================
    log(f"[Double Encryption] Strategy 4: Individual Wiener attacks")
    
    d1 = wiener_attack(e1, n)
    if d1:
        log(f"[Double Encryption] Found d1 = {d1}")
        intermediate = pow(c, d1, n)  # m^e2 mod n
        
        d2 = wiener_attack(e2, n)
        if d2:
            log(f"[Double Encryption] Found d2 = {d2}")
            m = pow(intermediate, d2, n)
            return m
    
    # Try other order
    d2 = wiener_attack(e2, n)
    if d2:
        log(f"[Double Encryption] Found d2 = {d2}")
        intermediate = pow(c, d2, n)  # m^e1 mod n
        
        d1 = wiener_attack(e1, n)
        if d1:
            log(f"[Double Encryption] Found d1 = {d1}")
            m = pow(intermediate, d1, n)
            return m
    
    # =============================================
    # STRATEGY 5: Factorization (last resort)
    # =============================================
    log(f"[Double Encryption] Strategy 5: Factorization")
    
    try:
        from .factorize import smart_factor_n
        p, q = smart_factor_n(n, use_factordb=True)
        
        if p and q:
            log(f"[Double Encryption] Factored n: p={p.bit_length()} bits, q={q.bit_length()} bits")
            
            phi = (p - 1) * (q - 1)
            
            # Try with e_total
            if math.gcd(e_total, phi) == 1:
                d_total = mod_inverse(e_total, phi)
                m = pow(c, d_total, n)
                return m
            
            # Try with e1 then e2
            if math.gcd(e1, phi) == 1:
                d1 = mod_inverse(e1, phi)
                intermediate = pow(c, d1, n)
                
                if math.gcd(e2, phi) == 1:
                    d2 = mod_inverse(e2, phi)
                    m = pow(intermediate, d2, n)
                    return m
    except Exception as e:
        log(f"[Double Encryption] Factorization failed: {e}")
    
    log(f"[Double Encryption] ❌ All attacks failed")
    return None
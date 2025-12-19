"""Double Encryption Attack"""

import gmpy2
import math
from typing import Optional, Callable
from ..utils.helpers import continued_fraction, convergents
from .low_exponent import low_exponent_attack
from .wiener import wiener_attack
from ..factorization.smart_factor import smart_factor_n
from ..utils.math_utils import mod_inverse

def double_encryption_attack(
    n: int,
    e1: int,
    e2: int,
    c: int,
    log_callback: Optional[Callable] = None
) -> Optional[int]:
    
    def log(msg: str):
        if log_callback:
            log_callback(msg)
    
    log(f"[Double Encryption] Starting attack with identical n={n.bit_length()}-bit, e1={e1}, e2={e2}")
    
    # STRATEGY 1: DIRECT WIENER ATTACK ON e_total
    log(f"[Double Encryption] Strategy 1: Direct Wiener attack on e_total = e1 * e2")
    e_total = e1 * e2
    
    log(f"[Double Encryption] Trying Wiener attack on e_total...")
    d_total = wiener_attack(e_total, n)
    
    if d_total:
        log(f"[Double Encryption] ✓ WIENER ATTACK SUCCESSFUL! Found d_total = {d_total}")
        m = pow(c, d_total, n)
        log(f"[Double Encryption] Direct decryption successful!")
        return m
    
    log(f"[Double Encryption] Direct Wiener attack on e_total failed")
    
    # STRATEGY 2: ALTERNATIVE - Try continued fractions manually
    log(f"[Double Encryption] Strategy 2: Alternative Wiener via continued fractions")
    
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
                            log(f"[Double Encryption] ✓ Found valid d from convergent {i}: d = {d}")
                            
                            # Decrypt
                            m = pow(c, d, n)
                            log(f"[Double Encryption] Decryption successful via alternative method!")
                            return m
                except:
                    continue
    
    # STRATEGY 3: LAYERED APPROACH (if one exponent is huge)
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
    

    # STRATEGY 4: Try Wiener on each exponent individually
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
    

    # STRATEGY 5: Factorization (last resort)
    log(f"[Double Encryption] Strategy 5: Factorization")
    
    try:
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
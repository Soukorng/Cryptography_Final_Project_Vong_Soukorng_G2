# rsa_core/attacks.py
from math import isqrt

def low_exponent_attack(e: int, n: int, c: int):
    """
    Attack when e is very small (e=3, e=5, etc.) and m^e < n.
    Also handles the case where m^e is slightly larger than n.
    """
    if e < 3 or e > 100:  # Only for small exponents
        return None
    
    # Try with gmpy2 for efficiency, fallback to Python
    try:
        import gmpy2
        # Try direct e-th root
        m, exact = gmpy2.iroot(c, e)
        if exact:
            return int(m)
        
        # If m^e was slightly larger than n, try c + k*n for small k
        for k in range(1, 1000):  # Try up to k=1000
            m_test, exact = gmpy2.iroot(c + k * n, e)
            if exact:
                return int(m_test)
    except ImportError:
        # Fallback to Python implementation
        # Binary search for e-th root
        def find_eth_root(num, e):
            low = 0
            high = 1
            while high ** e <= num:
                high <<= 1
            
            while low <= high:
                mid = (low + high) // 2
                mid_pow = mid ** e
                if mid_pow == num:
                    return mid, True
                elif mid_pow < num:
                    low = mid + 1
                else:
                    high = mid - 1
            return high, False
        
        # Try direct e-th root
        m, exact = find_eth_root(c, e)
        if exact:
            return m
        
        # If m^e was slightly larger than n, try c + k*n for small k
        for k in range(1, 1000):
            m_test, exact = find_eth_root(c + k * n, e)
            if exact:
                return m_test
    
    return None

def wiener_attack(e: int, n: int):
    """
    Wiener's attack to recover d when d is small.
    Returns d if found, None otherwise.
    """
    if not e or not n or e >= n or e <= 1:
        return None
    
    # Build continued fraction expansion of e/n
    cf = []
    a, b = e, n
    while b:
        q = a // b
        cf.append(q)
        a, b = b, a % b
    
    # Generate convergents
    h_n2, k_n2 = 0, 1   # h-2, k-2
    h_n1, k_n1 = 1, 0   # h-1, k-1
    
    for q in cf:
        h = q * h_n1 + h_n2
        k = q * k_n1 + k_n2
        
        # Update for next iteration
        h_n2, k_n2 = h_n1, k_n1
        h_n1, k_n1 = h, k
        
        # Skip trivial cases - FIXED: check both k AND h
        if k == 0 or h == 0:  # Added check for h == 0
            continue
        
        # Check if k is a candidate for d
        # We need: e*d ≡ 1 (mod φ(n))
        # If k is d, then e*k - 1 is divisible by h, and (e*k - 1)/h = φ(n)
        if (e * k - 1) % h == 0:
            phi = (e * k - 1) // h
            
            # Reconstruct p and q from n and phi
            # Solve: x^2 - (n - phi + 1)x + n = 0
            s = n - phi + 1
            discriminant = s * s - 4 * n
            
            if discriminant < 0:
                continue
            
            # Check if discriminant is a perfect square
            sqrt_disc = isqrt(discriminant)
            if sqrt_disc * sqrt_disc != discriminant:
                continue
            
            # Calculate p and q
            p_candidate = (s + sqrt_disc) // 2
            q_candidate = (s - sqrt_disc) // 2
            
            # Verify that p * q == n
            if p_candidate * q_candidate == n and p_candidate > 1 and q_candidate > 1:
                return int(k)  # k is d
    
    return None

def double_encryption_attack(n: int, e1: int, e2: int, c: int, log_callback=None):
    """
    Attack double encryption: c = (m^e1)^e2 mod n = m^(e1*e2) mod n
    
    Strategy:
    1. If either e1 or e2 is huge, try Wiener attack on the huge exponent
    2. Try Wiener attack on e_total = e1 * e2
    
    Returns m if successful, None otherwise.
    """
    # Helper function for logging
    def log(msg):
        if log_callback:
            log_callback(msg)
    
    log(f"[Double Encryption] Starting attack with n={n.bit_length()}-bit, e1={e1}, e2={e2}")
    
    # =============================================
    # STRATEGY 1: Try Wiener on huge exponent (if any)
    # =============================================
    # Check which exponent is huge (if any)
    huge_exp = None
    huge_label = None
    small_exp = None
    small_label = None
    
    # Consider exponent as "huge" if > 10^100 or > 1000 bits
    threshold = 10**100
    
    if e1 > threshold or e1.bit_length() > 1000:
        huge_exp, huge_label = e1, "e1"
        small_exp, small_label = e2, "e2"
        log(f"[Double Encryption] e1 is huge ({e1.bit_length()} bits), e2 is small")
    elif e2 > threshold or e2.bit_length() > 1000:
        huge_exp, huge_label = e2, "e2"
        small_exp, small_label = e1, "e1"
        log(f"[Double Encryption] e2 is huge ({e2.bit_length()} bits), e1 is small")
    else:
        log(f"[Double Encryption] Neither exponent is particularly huge")
    
    # If we found a huge exponent, try Wiener attack on it
    if huge_exp:
        log(f"[Double Encryption] Step 1: Trying Wiener attack on {huge_label}...")
        d_huge = wiener_attack(huge_exp, n)
        
        if d_huge:
            log(f"[Double Encryption] SUCCESS! Found d_{huge_label} = {d_huge}")
            
            # Decrypt first layer: intermediate = c^d_huge mod n = m^small_exp mod n
            intermediate = pow(c, d_huge, n)
            log(f"[Double Encryption] Decrypted first layer: intermediate = m^{small_exp} mod n")
            
            # Now try to get d for the small exponent
            log(f"[Double Encryption] Step 2: Trying to get d_{small_label}...")
            
            # First try Wiener on the small exponent
            d_small = wiener_attack(small_exp, n)
            if d_small:
                log(f"[Double Encryption] SUCCESS! Found d_{small_label} = {d_small}")
                # Final decryption: m = intermediate^d_small mod n
                m = pow(intermediate, d_small, n)
                log(f"[Double Encryption] Layered decryption successful!")
                return m
            else:
                log(f"[Double Encryption] Wiener on {small_label} failed. Need to factor n for d_{small_label}")
                # Could try factoring here if needed
                # But for now, we'll continue to other strategies
    
    # =============================================
    # STRATEGY 2: Try Wiener on e_total = e1 * e2
    # =============================================
    log(f"[Double Encryption] Step 3: Trying direct Wiener attack on e_total = e1 * e2")
    e_total = e1 * e2
    log(f"[Double Encryption] e_total bit length: {e_total.bit_length()} bits")
    
    d_total = wiener_attack(e_total, n)
    if d_total:
        log(f"[Double Encryption] SUCCESS! Found d_total = {d_total}")
        # Direct decryption: m = c^d_total mod n
        m = pow(c, d_total, n)
        log(f"[Double Encryption] Direct decryption successful!")
        return m
    
    # =============================================
    # STRATEGY 3: Try Wiener on each exponent individually
    # =============================================
    log(f"[Double Encryption] Step 4: Trying Wiener attack on each exponent individually")
    
    # Try e1
    d1 = wiener_attack(e1, n)
    if d1:
        log(f"[Double Encryption] Found d1 = {d1} via Wiener attack")
        # This gives us: c1 = c^d1 mod n = m^e2 mod n
        # But we still need d2
        log(f"[Double Encryption] Would need d2 to complete decryption")
    
    # Try e2
    d2 = wiener_attack(e2, n)
    if d2:
        log(f"[Double Encryption] Found d2 = {d2} via Wiener attack")
        # This gives us: c1 = c^d2 mod n = m^e1 mod n
        # But we still need d1
        log(f"[Double Encryption] Would need d1 to complete decryption")
    
    log(f"[Double Encryption] All attacks failed")
    return None
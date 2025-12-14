from .factorize import smart_factor_n, smart_factor_phi
from .compute_d import compute_d_from_phi, compute_d
from .utils import mod_inverse
from typing import Optional, Tuple
from math import isqrt
import gmpy2

# rsa_core/decrypt.py
def rsa_decrypt(c: int, d: int, n: int) -> int:
    return pow(c, d, n)

# rsa_core/decrypt.py - Add optional logging
def rsa_crt_decrypt(c: int, p: int, q: int, dp: int, dq: int, verbose=False) -> int:
    """
    RSA decryption using Chinese Remainder Theorem (CRT)
    Given: c, p, q, dp = d mod (p-1), dq = d mod (q-1)
    Returns: m = c^d mod n
    """
    if verbose:
        print(f"[CRT] p = {p}")
        print(f"[CRT] q = {q}")
        print(f"[CRT] dp = {dp}")
        print(f"[CRT] dq = {dq}")
        print(f"[CRT] c = {c}")
    
    # Step 1: Compute m1 = c^dp mod p
    m1 = pow(c, dp, p)
    if verbose:
        print(f"[CRT] m1 = c^dp mod p = {c}^{dp} mod {p} = {m1}")
    
    # Step 2: Compute m2 = c^dq mod q
    m2 = pow(c, dq, q)
    if verbose:
        print(f"[CRT] m2 = c^dq mod q = {c}^{dq} mod {q} = {m2}")
    
    # Step 3: Compute q_inv = q^(-1) mod p
    def mod_inverse(a, m):
        # Extended Euclidean Algorithm
        def egcd(a, b):
            if a == 0:
                return b, 0, 1
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y
        
        g, x, _ = egcd(a, m)
        if g != 1:
            raise ValueError(f"No modular inverse for {a} mod {m}")
        return x % m
    
    q_inv = mod_inverse(q, p)
    if verbose:
        print(f"[CRT] q_inv = q^(-1) mod p = {q}^(-1) mod {p} = {q_inv}")
    
    # Step 4: Compute h = (q_inv * (m1 - m2)) mod p
    h = (q_inv * (m1 - m2)) % p
    if verbose:
        print(f"[CRT] h = (q_inv * (m1 - m2)) mod p = ({q_inv} * ({m1} - {m2})) mod {p} = {h}")
    
    # Step 5: Compute m = m2 + h * q
    m = m2 + h * q
    if verbose:
        print(f"[CRT] m = m2 + h * q = {m2} + {h} * {q} = {m}")
    
    return m

def decrypt_with_phi(e: int = None, phi: int = None, n: int = None, 
                     d: int = None, c: int = None, log_callback=None):
    """
    Unified φ(n) decryption function with enhanced special case handling.
    """
    def log(msg):
        if log_callback:
            log_callback(msg)
    
    log(f"[Decrypt with φ] Starting with e={e}, φ={phi.bit_length() if phi else 0}-bit")
    
    if not e or not phi or not c:
        log("[Decrypt with φ] ❌ Missing required parameters (e, φ, c)")
        return None, None, None, None
    
    # =================== CASE 1: HAVE n ===================
    if n:
        log("[Decrypt with φ] Case 1: We have n - computing d from φ")
        log(f"   • n = {n.bit_length()}-bit")
        
        try:
            if not d:
                d = compute_d_from_phi(phi, e)
                log(f"   • Computed d = {d.bit_length()}-bit")
            
            # Verify e*d ≡ 1 mod φ
            if (e * d) % phi != 1:
                log(f"   • e*d mod φ = {(e * d) % phi} ≠ 1")
            
            # Decrypt
            m = pow(c, d, n)
            log(f"   • Decrypted message = {m.bit_length()}-bit")
            
            # Try to factor n
            p, q = None, None
            try:
                p, q = smart_factor_n(n, use_factordb=False)
                if p and q:
                    log(f"   • Factored n: p={p.bit_length()}-bit, q={q.bit_length()}-bit")
            except:
                pass
            
            return m, n, p, q
        
        except Exception as ex:
            log(f"   ❌ Error in Case 1: {ex}")
            return None, None, None, None
    
    # =================== CASE 2: HAVE d (but no n) ===================
    elif d:
        log("[Decrypt with φ] Case 2: Have d but no n - attempting to recover n from φ")
        log(f"   • d = {d.bit_length()}-bit")
        
        try:
            # Verify e*d ≡ 1 mod φ
            ed_mod_phi = (e * d) % phi
            if ed_mod_phi != 1:
                log(f"   • e*d mod φ = {ed_mod_phi} ≠ 1")
            else:
                log("   ✓ Verified: e*d ≡ 1 mod φ")
            
            # First try to recover p and q using smart_factor_phi
            log("   • Attempting to recover p and q from φ using smart_factor_phi...")
            p, q = smart_factor_phi(phi, use_factordb=True, log_callback=log)
            
            if p and q:
                log(f"   ✓ Successfully recovered p and q from φ!")
                log(f"   • p = {p.bit_length()}-bit, q = {q.bit_length()}-bit")
                
                # Compute n
                n = p * q
                log(f"   • Computed n = p*q = {n.bit_length()}-bit")
                
                # Verify φ
                if (p - 1) * (q - 1) != phi:
                    log(f"   • (p-1)(q-1) ≠ φ")
                
                # Decrypt
                m = pow(c, d, n)
                log(f"   • Decrypted message = {m.bit_length()}-bit")
                
                return m, n, p, q
            
            # =================== CASE 3: SPECIAL φ STRUCTURE ===================
            # If smart_factor_phi failed, try direct quadratic solving
            # This handles cases like p = 2q + 1 from the walkthrough
            log("   • Case 3: Trying direct quadratic solving for special φ structure...")
            
            # We know φ = (p-1)(q-1)
            # Let's try to solve for p and q directly
            
            # Method: Since φ = pq - p - q + 1
            # Let s = p + q, then φ = n - s + 1, so n = φ + s - 1
            # Also, (p - q)² = s² - 4n = s² - 4(φ + s - 1) = s² - 4s - 4φ + 4
            
            # We need s such that s² - 4s - 4φ + 4 is a perfect square
            
            
            
            # Compute k = (e*d - 1) // φ
            ed_minus_1 = e * d - 1
            if ed_minus_1 % phi == 0:
                k = ed_minus_1 // phi
                log(f"   • k = (e*d - 1)/φ = {k}")
            
            # Estimate s ≈ 2√φ (since p and q are roughly √n and n ≈ φ)
            sqrt_phi = gmpy2.isqrt(phi)
            
            # Search for s in a reasonable range
            # s = p + q should be even (since p and q are odd)
            s_start = 2 * sqrt_phi - 10000
            s_end = 2 * sqrt_phi + 10000
            
            # Ensure s_start is even and positive
            if s_start % 2 != 0:
                s_start += 1
            if s_start < 2:
                s_start = 2
            
            log(f"   • Searching for s in range [{s_start}, {s_end}] (step 2)")
            
            for s in range(s_start, s_end + 1, 2):
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
                
                # Check if they're prime
                if gmpy2.is_prime(p_candidate) and gmpy2.is_prime(q_candidate):
                    # Verify φ
                    if (p_candidate - 1) * (q_candidate - 1) == phi:
                        n_candidate = p_candidate * q_candidate
                        log(f"   ✓ Found p and q via quadratic solving!")
                        log(f"   • p = {p_candidate.bit_length()}-bit, q = {q_candidate.bit_length()}-bit")
                        log(f"   • n = {n_candidate.bit_length()}-bit")
                        
                        # Decrypt
                        m = pow(c, d, n_candidate)
                        log(f"   • Decrypted message = {m.bit_length()}-bit")
                        
                        return m, n_candidate, p_candidate, q_candidate
            
            log("   ❌ All methods failed to recover n from φ")
            
        except Exception as ex:
            log(f"   ❌ Error in Case 2/3: {ex}")
            import traceback
            log(traceback.format_exc())
            return None, None, None, None
    
    else:
        log("[Decrypt with φ] ❌ Need either n or d to proceed")
    
    return None, None, None, None

def decrypt_with_pq(c: int, p: int, q: int, e: int = None, d: int = None, n: int = None, 
                   log_callback=None):
    """
    Standard RSA decryption with p and q.
    If n is not provided, compute n = p * q.
    If d is not provided but e is, compute d from p, q, e.
    """
    def log(msg):
        if log_callback:
            log_callback(msg)
    
    log(f"[Decrypt with p,q] Starting with p={p.bit_length()}-bit, q={q.bit_length()}-bit")
    
    if not c or not p or not q:
        log("[Decrypt with p,q] ❌ Missing required parameters (c, p, q)")
        return None, None, None
    
    if not d and not e:
        log("[Decrypt with p,q] ❌ Need either d or e to compute decryption exponent")
        return None, None, None
    
    try:
        # Compute n if not provided
        if not n:
            n = p * q
            log(f"   • Computed n = p*q = {n.bit_length()}-bit")
        else:
            log(f"   • Using provided n = {n.bit_length()}-bit")
        
        # Verify n = p * q
        if n != p * q:
            log(f"   ⚠️  Warning: Provided n ({n}) does not equal p*q ({p*q})")
        
        # Compute d if not provided
        if not d and e:
            d = compute_d(p, q, e)
            log(f"   • Computed d from p,q,e = {d.bit_length()}-bit")
        elif d:
            log(f"   • Using provided d = {d.bit_length()}-bit")
        
        # Decrypt
        m = pow(c, d, n)
        
        log(f"   • Decrypted message = {m.bit_length()}-bit integer")
        
        return m, n, d
    
    except Exception as ex:
        log(f"   ❌ Error in standard decryption: {ex}")
        return None, None, None
    
def recover_prime_from_n(n: int, known_prime: int, log_callback=None) -> Optional[int]:
    """
    Recover the other prime when n and one prime are given.
    
    Args:
        n: RSA modulus
        known_prime: Either p or q
        log_callback: Optional logging function
    
    Returns:
        The other prime or None
    """
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

def decrypt_with_n_and_prime(c: int, n: int, prime: int, e: int = None, d: int = None, 
                           log_callback=None) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """
    Decrypt when we have n and one prime (p or q).
    Automatically recovers the other prime and decrypts.
    
    Returns:
        Tuple of (message, n, d) or (None, None, None)
    """
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
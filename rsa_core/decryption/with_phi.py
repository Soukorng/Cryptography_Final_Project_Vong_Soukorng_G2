"""Decryption using phi (φ)"""

import traceback
from typing import Optional, Tuple
from ..decryption.standard import compute_d_from_phi
from ..factorization.smart_factor import smart_factor_phi

def decrypt_with_phi(
    e: int = None,
    phi: int = None,
    n: int = None,
    d: int = None,
    c: int = None,
    log_callback=None
) -> Tuple[Optional[int], Optional[int], Optional[int], Optional[int]]:
    """Decrypt using φ (Euler's Totient)"""
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
            
            return m, n, None, None
        
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

        except Exception as ex:
            log(f"   ❌ Error in Case 2: {ex}")
            log(traceback.format_exc())
            return None, None, None, None
    
    else:
        log("[Decrypt with φ] ❌ Need either n or d to proceed")
    
    return None, None, None, None
"""Decryption using Prime Factors (p and q)"""

from typing import Optional, Tuple
from ..decryption.standard import compute_d

def decrypt_with_pq(
    c: int,
    p: int,
    q: int,
    e: int = None,
    d: int = None,
    n: int = None,
    log_callback=None
) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Decrypt using prime factors p and q"""
    
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
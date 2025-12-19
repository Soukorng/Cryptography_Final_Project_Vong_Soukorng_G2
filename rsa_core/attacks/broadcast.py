"""Håstad Broadcast Attack"""

import gmpy2
from typing import Optional, List, Callable
from ..utils.helpers import chinese_remainder_theorem

def hastad_broadcast_attack(
    e: int,
    ciphertexts: List[int],
    moduli: List[int] = None,
    log_callback: Optional[Callable] = None
) -> Optional[int]:
    
    def log(msg: str):
        if log_callback:
            log_callback(msg)
    
    log(f"[Håstad] Starting broadcast attack with e={e}")
    
    # If moduli not provided, assume all use same n (from single modulus scenario)
    if moduli is None:
        log(f"[Håstad] No moduli provided, using single modulus scenario")
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
        
        # Combine ciphertexts using CRT
        m_pow_e = chinese_remainder_theorem(c_list, n_list)
        
        if m_pow_e is None:
            log("[Håstad] CRT failed")
            return None
        
        log(f"[Håstad] Recovered m^{e} = {m_pow_e}")
        log(f"[Håstad] m^{e} is {m_pow_e.bit_length()}-bits")
        
        # Step 2: Take the e-th root over integers
        log(f"[Håstad] Computing {e}-th root...")
        
        try:
            # Use gmpy2 for efficient root computation
            m, exact = gmpy2.iroot(m_pow_e, e)
            
            if exact:
                log(f"[Håstad] ✓ Success! Found exact {e}-th root")
                return int(m)
            else:
                log(f"[Håstad] Not an exact {e}-th root")
                
                # Try nearby values (in case of padding)
                log(f"[Håstad] Trying nearby values (for potential padding)...")
                for offset in [0, 1, -1, 2, -2]:
                    m_test, exact_test = gmpy2.iroot(m_pow_e + offset, e)
                    if exact_test:
                        log(f"[Håstad] ✓ Found exact root with offset {offset}")
                        return int(m_test)
        
        except Exception as root_ex:
            log(f"[Håstad] Error computing root: {root_ex}")
            return None
    
    except Exception as ex:
        log(f"[Håstad] Error in broadcast attack: {ex}")
    
    return None
"""Chinese Remainder Theorem Decryption"""

from ..utils.math_utils import mod_inverse

def rsa_crt_decrypt(
    ciphertext: int,
    p: int,
    q: int,
    dp: int,
    dq: int,
    verbose: bool = False
) -> int:
    """
    RSA decryption using Chinese Remainder Theorem (CRT)
    """
    if verbose:
        print(f"[CRT] p = {p}")
        print(f"[CRT] q = {q}")
        print(f"[CRT] dp = {dp}")
        print(f"[CRT] dq = {dq}")
        print(f"[CRT] c = {ciphertext}")
    
    # Step 1: Compute m1 = c^dp mod p
    m1 = pow(ciphertext, dp, p)
    
    # Step 2: Compute m2 = c^dq mod q
    m2 = pow(ciphertext, dq, q)
    
    # Step 3: Compute q_inv = q^(-1) mod p
    q_inv = mod_inverse(q, p)
    
    # Step 4: Compute h = (q_inv * (m1 - m2)) mod p
    h = (q_inv * (m1 - m2)) % p
    
    # Step 5: Compute m = m2 + h * q
    m = m2 + h * q
    
    return m
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
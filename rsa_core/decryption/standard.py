"""Standard RSA Decryption"""

from ..utils.math_utils import mod_inverse

def rsa_decrypt(ciphertext: int, private_key: int, modulus: int) -> int:
    """Standard RSA decryption"""
    return pow(ciphertext, private_key, modulus)

def compute_d(p: int, q: int, e: int) -> int:
    """Compute private exponent d from primes p and q"""
    if p == q:
        phi = p * (p - 1)
    else:
        phi = (p - 1) * (q - 1)
    return mod_inverse(e, phi)

def compute_d_from_phi(phi: int, e: int) -> int:
    """Compute private exponent d from phi"""
    return mod_inverse(e, phi)
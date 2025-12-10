# rsa_core/compute_d.py
from .utils import mod_inverse

def compute_d(p: int, q: int, e: int) -> int:
    if p == q:
        # n = p^2
        phi = p * (p - 1)
    else:
        phi = (p - 1) * (q - 1)
    return mod_inverse(e, phi)
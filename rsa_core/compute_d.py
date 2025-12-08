from .utils import mod_inverse

def compute_d(p: int, q: int, e: int) -> int:
    phi = (p - 1) * (q - 1)
    return mod_inverse(e, phi)
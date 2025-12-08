def rsa_decrypt(c: int, d: int, n: int) -> int:
    return pow(c, d, n)
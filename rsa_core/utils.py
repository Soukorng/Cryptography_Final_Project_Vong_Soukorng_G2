from math import gcd as python_gcd

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def mod_inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m

def is_perfect_square(n):
    if n < 0:
        return False
    root = int(n**0.5)
    return root * root == n
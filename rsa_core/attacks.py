from math import isqrt

def wiener_attack(e: int, n: int):
    """
    Safe Wiener's attack – recovers d only when d is small.
    Fixed all bugs: no division by zero, no memory error.
    """
    if not e or not n or e >= n or e <= 1:
        return None

    # Build continued fraction coefficients of e/n
    cf = []
    a, b = e, n
    while b:
        cf.append(a // b)
        a, b = b, a % b

    # Generate convergents h/k ≈ e/n
    h_n2, k_n2 = 0, 1   # h-2/k-2
    h_n1, k_n1 = 1, 0   # h-1/k-1

    for q in cf:
        h = q * h_n1 + h_n2
        k = q * k_n1 + k_n2

        # Update for next round
        h_n2, k_n2 = h_n1, k_n1
        h_n1, k_n1 = h, k

        # Safety: prevent division by zero
        if k == 0 or h == 0:
            continue

        # Check if this convergent gives ed ≡ 1 (mod φ(n))
        if (e * k - 1) % h == 0:
            phi = (e * k - 1) // h

            # Reconstruct p and q from quadratic equation
            s = n - phi + 1
            disc = s*s - 4*n
            if disc <= 0:
                continue

            sqrt_disc = isqrt(disc)
            if sqrt_disc * sqrt_disc != disc:
                continue

            p = (s + sqrt_disc) // 2
            q = (s - sqrt_disc) // 2

            if p * q == n and p > 1 and q > 1:
                return int(k)  # this k is d

    return None

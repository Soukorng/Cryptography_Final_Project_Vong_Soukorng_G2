import math
import random
import gmpy2
import threading

gmpy2.get_context().precision = 4096

# ==========================================================
#                 POLLARD RHO  (Classic)
# ==========================================================
def pollard_rho(n):
    if n % 2 == 0: return 2
    if n % 3 == 0: return 3

    def f(x): return (x * x + 1) % n

    for seed in range(5):  # multiple seeds
        x = random.randrange(2, n - 1)
        y = x
        d = 1
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)
            if d == n: break
        if 1 < d < n:
            return d
    return None

# ==========================================================
#                POLLARD RHO (Brent Version)
# ==========================================================
def pollard_rho_brent(n):
    if n % 2 == 0: return 2
    if n % 3 == 0: return 3

    y, c, m = random.randrange(1, n), random.randrange(1, n), random.randrange(1, n)
    g, r, q = 1, 1, 1

    while g == 1:
        x = y
        for _ in range(r):
            y = (y * y + c) % n

        k = 0
        while k < r and g == 1:
            ys = y
            for _ in range(min(m, r - k)):
                y = (y * y + c) % n
                q = q * abs(x - y) % n
            g = math.gcd(q, n)
            k += m
        r <<= 1

    if g == n:
        # retry fallback
        while True:
            ys = (ys * ys + c) % n
            g = math.gcd(abs(x - ys), n)
            if g > 1:
                break
    return g

# ==========================================================
#             MULTI-THREAD ECM (MAX SAFETY)
# ==========================================================
ECM_FOUND = None

def _ecm_thread(n, B1, curves=50):
    global ECM_FOUND
    for _ in range(curves):
        if ECM_FOUND: 
            return
        try:
            f = int(gmpy2.ecm(n, B1=B1))
            if 1 < f < n:
                ECM_FOUND = f
                return
        except:
            pass

def threaded_ecm(n, B1=50_000, threads=4, curves_per_thread=20):
    """
    Safe ECM — capped work, multi-threaded.
    Never freezes GUI.
    """
    global ECM_FOUND
    ECM_FOUND = None

    t_list = []
    for _ in range(threads):
        t = threading.Thread(target=_ecm_thread, args=(n, B1, curves_per_thread))
        t.daemon = True
        t.start()
        t_list.append(t)

    for t in t_list:
        t.join(0.5)  # join with timeout, never block fully

    return ECM_FOUND

# ==========================================================
#              MAIN UNIVERSAL FACTORIZER
# ==========================================================
def smart_factor_n(n: int):
    """
    TURBO AUTO-FACTOR ENGINE
    -----------------------------------------------------
    Uses:
        • Trial division (small)
        • Pollard Rho
        • Pollard Rho Brent (better)
        • Fermat (for close primes)
        • Multi-threaded ECM (safe)
        • Auto bit-size selection
    """
    n = int(n)
    if n <= 1:
        return None, None

    bits = n.bit_length()

    # -------- trivial ----------
    if n % 2 == 0: return 2, n // 2
    if n % 3 == 0: return 3, n // 3

    # ==================================================
    # SMALL (< 100 bits) → Instant trial
    # ==================================================
    if bits <= 100:
        limit = min(5_000_000, math.isqrt(n) + 1)
        i = 5
        while i <= limit:
            if n % i == 0: return i, n // i
            if n % (i + 2) == 0: return i + 2, n // (i + 2)
            i += 6

    # ==================================================
    # MEDIUM (100–250 bits) → Pollard Rho
    # ==================================================
    if bits <= 250:
        f = pollard_rho(n)
        if f:
            return min(f, n // f), max(f, n // f)

        f = pollard_rho_brent(n)
        if f:
            return min(f, n // f), max(f, n // f)

        # Fermat attempt (p≈q)
        a = math.isqrt(n)
        for _ in range(200_000):
            a += 1
            b2 = a*a - n
            b = math.isqrt(b2)
            if b*b == b2:
                p, q = a - b, a + b
                return min(p, q), max(p, q)

    # ==================================================
    # LARGE (250–1024 bits) → Multi-threaded ECM
    # ==================================================
    if bits <= 1024:
        f = threaded_ecm(n, B1=100_000, threads=6, curves_per_thread=30)
        if f:
            return min(f, n // f), max(f, n // f)
        return None, None

    # ==================================================
    # HUGE (> 1024 bits) → Stop early (avoid GUI freeze)
    # ==================================================
    return None, None

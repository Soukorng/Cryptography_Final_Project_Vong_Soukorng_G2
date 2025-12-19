"""Elliptic Curve Method for Factorization"""

import threading
import time
import gmpy2
from typing import Optional

ECM_FOUND = None
ECM_LOCK = threading.Lock()

def _ecm_thread(n: int, B1: int, curves: int = 50):
    """Secure ECM worker thread with error handling."""
    global ECM_FOUND
    
    for _ in range(curves):
        with ECM_LOCK:
            if ECM_FOUND:
                return
        
        try:
            # Use gmpy2's ECM with error handling
            f = int(gmpy2.ecm(n, B1=B1))
            if 1 < f < n:
                with ECM_LOCK:
                    ECM_FOUND = f
                return
        except Exception:
            continue

def threaded_ecm(
    n: int,
    B1: int = 50000,
    threads: int = 4,
    curves_per_thread: int = 20,
    timeout: float = 2.0
) -> Optional[int]:
    """
    Safe ECM — capped work, multi-threaded, with timeout.
    Never freezes GUI.
    """
    global ECM_FOUND
    ECM_FOUND = None

    # Security: Validate input parameters
    if n <= 1 or threads <= 0 or curves_per_thread <= 0:
        return None
    
    t_list = []
    for _ in range(min(threads, 8)):  # Security: Cap maximum threads
        t = threading.Thread(target=_ecm_thread, args=(n, B1, curves_per_thread))
        t.daemon = True
        t.start()
        t_list.append(t)

    # Wait with timeout to prevent hanging
    start_time = time.time()
    while time.time() - start_time < timeout:
        if ECM_FOUND:
            break
        time.sleep(0.1)

    # Clean up threads
    for t in t_list:
        t.join(timeout=0.1)

    return ECM_FOUND
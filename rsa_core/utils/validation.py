"""RSA Parameter Validation"""

def validate_rsa_params(**kwargs) -> bool:
    """
    Validate RSA parameters for security.
    Returns True if parameters are valid.
    """
    for key, value in kwargs.items():
        if value is None:
            continue
        
        if not isinstance(value, int):
            return False
        
        # Check ranges
        if key in ['n', 'p', 'q'] and value <= 0:
            return False
        
        if key == 'e' and (value <= 1 or value >= kwargs.get('n', 2**1024)):
            return False
        
        if key == 'd' and value <= 0:
            return False
    
    # Specific checks
    if 'n' in kwargs and kwargs['n'] is not None:
        n = kwargs['n']
        
        # Check n is odd (except for attack scenarios)
        if n % 2 == 0 and 'e' in kwargs:
            print("[SECURITY] WARNING: Even modulus detected")
        
        # Check minimum size
        if n.bit_length() < 256:
            print(f"[SECURITY] WARNING: Small modulus: {n.bit_length()} bits")
    
    return True
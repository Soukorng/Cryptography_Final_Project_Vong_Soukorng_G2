"""Data Conversion Utilities"""

def int_to_bytes(n: int) -> bytes:
    """Convert integer to bytes"""
    if n == 0:
        return b'\x00'
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def bytes_to_hex(b: bytes) -> str:
    """Convert bytes to hexadecimal string"""
    return b.hex()

def try_decode(b: bytes) -> str:
    """Try to decode bytes to UTF-8 string"""
    try:
        return b.decode('utf-8', errors='ignore').strip()
    except:
        return "<binary/non-utf8>"
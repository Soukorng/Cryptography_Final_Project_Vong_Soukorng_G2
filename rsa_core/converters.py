def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def try_decode(b: bytes) -> str:
    try:
        return b.decode('utf-8', errors='ignore').strip()
    except:
        return "<binary/non-utf8>"

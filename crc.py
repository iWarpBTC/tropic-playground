# === CRC-16/CCITT-FALSE ===
def crc16_byte(data, crc):
    crc ^= data << 8
    for _ in range(8):
        if crc & 0x8000:
            crc = (crc << 1) ^ 0x8005
        else:
            crc <<= 1
    return crc & 0xFFFF

def calc_crc(frame: bytes) -> int:
    crc = 0x0000
    for b in frame:
        crc = crc16_byte(b, crc)
    return ((crc & 0xFF) << 8) | (crc >> 8)

def add_crc(frame: bytes) -> bytes:
    crc = calc_crc(frame)
    return frame + bytes([(crc >> 8) & 0xFF, crc & 0xFF])
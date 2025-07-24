
import serial
from crc import add_crc, calc_crc

def send_frame(frame: bytes, ser: serial.Serial):
    full_frame = bytes([0xA5, len(frame)]) + frame
    ser.write(full_frame)

def get_frame(req_id: int, req_data: bytes) -> bytes:
    frame = bytes([req_id, len(req_data)]) + req_data
    return add_crc(frame)

def get_resend_response(ser: serial.Serial):
    frame = get_frame(0x10, b'')
    send_frame(frame, ser)
    return read_frame(ser)

def read_frame(ser: serial.Serial) -> bytes:
    prefix = ser.read(2)
    if len(prefix) != 2:
        raise RuntimeError("Neúplný prefix")
    if prefix[0] != 0x5A:
        raise RuntimeError(f"Odpověď nezačíná bajtem 0x5A (dostali jsme {prefix[0]:02X})")
    resp_len = prefix[1]
    response = ser.read(resp_len)
    if len(response) != resp_len:
        raise RuntimeError("Neúplná odpověď z Arduina")
    if len(response) < 4:
        raise RuntimeError("Odpověď je příliš krátká (méně než 4 bajty)")
    
    status = response[0]
    length = response[1]
    if status != 0x01 and status != 0x02:
        print(f"❌ Chyba v odpovědi: {status:02X}, očekáváno 0x01")
        print(" ".join(f"{b:02X}" for b in response))
        return b''
    if length != resp_len - 4:
        raise RuntimeError(f"Očekáváno {length} bajtů, dostáno {resp_len - 4}")

    payload = response[:-2]
    crc_recv = (response[-2] << 8) | response[-1]
    crc_calc = calc_crc(payload)
    if crc_calc == crc_recv:
        print(f"✅ CRC OK: {crc_recv:04X}")
        return payload[2:]
    else:
        raise RuntimeError(f"CRC nesouhlasí: očekáváno {crc_calc:04X}, dostáno {crc_recv:04X}")  
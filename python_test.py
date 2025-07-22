import serial
import time

from crc import add_crc, calc_crc
from utils import print_chip_id_struct, analyze_certs

# === Konfigurace ===
PORT = '/dev/tty.usbmodem141401'  # uprav dle potřeby
BAUDRATE = 115200
TIMEOUT = 2
DEBUG = False

def send_frame(frame: bytes, ser: serial.Serial):  
    full_frame = [0xA5, len(frame)] + list(frame)
    if DEBUG:
        print("📤 Posílám rámec na Arduino:")
        print(" ".join(f"{b:02X}" for b in full_frame))
    ser.write(bytes([0xA5, len(frame)]))
    ser.write(frame)

def read_frame(ser: serial.Serial) -> bytes:
    prefix = ser.read(2)
    if DEBUG:
        print(f"📥 Prefix ({len(prefix)} bajty): {' '.join(f'{b:02X}' for b in prefix)}")
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
    if status != 0x01:
        raise RuntimeError(f"Status: {status:02X}")
    if length != resp_len - 4:
        raise RuntimeError(f"Očekáváno {length} bajtů, dostáno {resp_len - 4}")

    payload = response[:-2]
    crc_recv = (response[-2] << 8) | response[-1]
    crc_calc = calc_crc(payload)
    if crc_calc == crc_recv:
        if DEBUG:
            print(f"✅ CRC OK: {crc_recv:04X}")
        return payload[2:]
    else:
        raise RuntimeError(f"CRC nesouhlasí: očekáváno {crc_calc:04X}, dostáno {crc_recv:04X}")  
    
def get_frame(req_id: int, req_data: bytes) -> bytes:
    frame = bytes([req_id, len(req_data)]) + req_data
    return add_crc(frame)

def get_chip_id(ser: serial.Serial):
    req_data = bytes([0x01, 0x00])
    frame = get_frame(0x01, req_data)
    send_frame(frame, ser)

    payload = read_frame(ser)

    # === Výpis ===
    # print("\n📥 Odpověď z TROPIC01:")
    # print(" ".join(f"{b:02X}" for b in payload))

    print_chip_id_struct(payload)

def format_version(payload):
    """Format payload like [00, 01, 03, 00] to '0.3.1'"""
    if len(payload) >= 4:
        return f"{payload[3]}.{payload[2]}.{payload[1]}"
    return "Unknown version"

def get_fw_ver(ser: serial.Serial):
    req_data = bytes([0x02, 0x00])
    frame = get_frame(0x01, req_data)
    send_frame(frame, ser)

    payload = read_frame(ser)
    if DEBUG:
        print("\n📥 Odpověď z TROPIC01:")
        print(" ".join(f"{b:02X}" for b in payload))
    print(f"🔢 Verze RISCV firmware: {format_version(payload)}")
    print()
    
    # Example of using the format_version function
    # test_payload = bytes([0x00, 0x01, 0x03, 0x00])
    # print(f"Formatted version: {format_version(test_payload)}")

    req_data = bytes([0x04, 0x00])
    frame = get_frame(0x01, req_data)
    send_frame(frame, ser)

    payload = read_frame(ser)
    if DEBUG:
        print("\n📥 Odpověď z TROPIC01:")
        print(" ".join(f"{b:02X}" for b in payload))
    print(f"🔢 Verze SPECT firmware: {format_version(payload)}")
    print()

def get_certs(ser: serial.Serial):
    req_data = bytes([0x00, 0x00])
    frame = get_frame(0x01, req_data)
    send_frame(frame, ser)

    payload = read_frame(ser)
    if DEBUG:
        print("\n📥 Odpověď z TROPIC01:")
        print(" ".join(f"{b:02X}" for b in payload))

    cert_store_ver = payload[0]
    if cert_store_ver != 0x01:
        print(f"❌ Cert store verze: {cert_store_ver}")
        return
    cert_count = payload[1]

    offset = 2
    cert_lenghts = []
    for _ in range(cert_count):
        cert_lenghts.append(payload[offset] << 8 | payload[offset + 1])
        offset += 2

    total_length = 0
    for lenght in cert_lenghts:
        print(f"📜 Certifikát {lenght} bajtů")
        total_length += lenght

    readed = len(payload[offset:])

    all_cert_data = bytearray(payload[offset:])
    block_index = 1

    while readed < total_length:
        req_data = bytes([0x00, block_index])
        frame = get_frame(0x01, req_data)
        send_frame(frame, ser)

        payload = read_frame(ser)
        if DEBUG:
            print(f"\n📥 {block_index}. blok:")
            print(" ".join(f"{b:02X}" for b in payload))

        all_cert_data.extend(payload)

        readed += len(payload)
        block_index += 1

    certs = []
    cert_offset = 0
    for i, length in enumerate(cert_lenghts):
        if cert_offset + length <= len(all_cert_data):
            cert_data = all_cert_data[cert_offset:cert_offset+length]
            certs.append(cert_data)
            print(f"✅ Certifikát {i+1}: {length} bajtů extrahován")
            cert_offset += length
        else:
            print(f"❌ Nedostatek dat pro certifikát {i+1}")
    
    return certs


# === Odeslání na Arduino ===
ser = serial.Serial(PORT, BAUDRATE, timeout=TIMEOUT)
time.sleep(2)  # počkej na reset

get_chip_id(ser)
get_fw_ver(ser)
certs = get_certs(ser)
analyze_certs(certs)

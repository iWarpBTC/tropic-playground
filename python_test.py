import serial
import time
# from crcmod.predefined import mkPredefinedCrcFun

# === Konfigurace ===
PORT = '/dev/tty.usbmodem141401'  # uprav dle potřeby
BAUDRATE = 115200
TIMEOUT = 2

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

# === Sestavení GET_INFO_REQ (na objekt 0x01: CHIP_ID) ===
# req_id = 0x01 (GET_INFO_REQ), len = 0x02, object_id = 0x01, block_index = 0x00
frame = bytes([0x01, 0x02, 0x01, 0x00])
frame_with_crc = add_crc(frame)

# === Odeslání na Arduino ===
ser = serial.Serial(PORT, BAUDRATE, timeout=TIMEOUT)
time.sleep(2)  # počkej na reset

full_frame = [0xA5, len(frame_with_crc)] + list(frame_with_crc)
print("📤 Posílám rámec na Arduino:")
print(" ".join(f"{b:02X}" for b in full_frame))
ser.write(bytes([0xA5, len(frame_with_crc)]))
ser.write(frame_with_crc)

# === Čtení odpovědi ===
prefix = ser.read(2)
print(f"📥 Prefix ({len(prefix)} bajty): {' '.join(f'{b:02X}' for b in prefix)}")
if len(prefix) != 2:
    print("❌ Nedostali jsme 2 bajty prefixu. Arduino buď neodpovědělo, nebo posílá méně.")
    exit(1)
if prefix[0] != 0x5A:
    print(f"❌ Odpověď nezačíná bajtem 0x5A (dostali jsme {prefix[0]:02X})")
    exit(1)

resp_len = prefix[1]
response = ser.read(resp_len)

if len(response) != resp_len:
    raise RuntimeError("Neúplná odpověď z Arduina")

# === Výpis ===
print("\n📥 Odpověď z TROPIC01:")
print(" ".join(f"{b:02X}" for b in response))

# === Kontrola CRC odpovědi ===
if resp_len < 4:
    raise RuntimeError("Odpověď je příliš krátká na CRC")

status = response[0]
length = response[1]
payload = response[2:-2]
crc_recv = (response[-2] << 8) | response[-1]

frame_for_crc = bytes([status, length]) + payload
crc_expected = calc_crc(frame_for_crc)

if crc_recv != crc_expected:
    raise RuntimeError(f"CRC nesouhlasí: očekáváno {crc_expected:04X}, dostáno {crc_recv:04X}")
else:
    print(f"✅ CRC OK: {crc_recv:04X}")
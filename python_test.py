import serial
import time
from datetime import datetime

def decode_provisioning_date(byte0: int, byte1: int) -> str:
    date_value = (byte0 << 8) | byte1
    year = (date_value // 1000) + 2023
    day_of_year = date_value % 1000

    is_leap = (year % 4 == 0)
    days_in_months = [31, 29 if is_leap else 28, 31, 30, 31, 30,
                      31, 31, 30, 31, 30, 31]
    month_names = [
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    ]

    month = 0
    while month < 12 and day_of_year > days_in_months[month]:
        day_of_year -= days_in_months[month]
        month += 1

    if month >= 12:
        return "Invalid date"
    return f"{month_names[month]} {day_of_year}, {year}"


def print_chip_id_struct(buffer: bytes):
    print("🔎 CHIP_ID STRUCT DUMP")

    # Version
    version = ".".join(str(b) for b in buffer[0:4])
    print(f"📌 CHIP ID Verze: {version}")

    # Factory info
    print("🏭 Informace o výrobě:", " ".join(f"{b:02X}" for b in buffer[4:20]))

    # Functional test info
    print("🔬 Informace o funkčním testu:", " ".join(f"{b:02X}" for b in buffer[20:28]))

    # Silicon revision
    silicon_rev = ''.join(chr(b) for b in buffer[28:32])
    print(f"🔲 Revize křemíku: {silicon_rev}")

    # Package type ID
    print(f"📦 ID typu balení: 0x{buffer[32]:02X}{buffer[33]:02X}")

    # Provisioning date
    prov_raw = f"0x{buffer[42]:02X}{buffer[43]:02X}"
    prov_decoded = decode_provisioning_date(buffer[42], buffer[43])
    print(f"🗓️ Datum provisioningu: {prov_raw}")
    print(f"🗓️ Datum provisioningu dekódováno: {prov_decoded}")

    # HSM version
    hsm_ver = f"{buffer[45]}.{buffer[46]}.{buffer[47]}"
    print(f"🔐 Verze HSM: {hsm_ver}")

    # Program version
    prog_ver = f"{buffer[49]}.{buffer[50]}.{buffer[51]}"
    print(f"📟 Verze programu: {prog_ver}")

    offset = 52

    # Serial Number
    print(f"🔢 Sériové číslo (SN): 0x{buffer[offset]:02X}")
    offset += 1

    # Fab ID
    print("🔢 Fab ID:", "".join(f"{buffer[offset + i]:02X}" for i in range(3)))
    offset += 3

    # Fab date
    fab_raw = f"0x{buffer[offset]:02X}{buffer[offset + 1]:02X}"
    fab_decoded = decode_provisioning_date(buffer[offset], buffer[offset + 1])
    print(f"📅 Fab datum raw: {fab_raw}")
    print(f"📅 Fab datum dekódováno: {fab_decoded}")
    offset += 2

    # Lot ID
    print("🧪 Lot ID:", "".join(f"{buffer[offset + i]:02X}" for i in range(5)))
    offset += 5

    # Wafer ID
    print(f"💿 Wafer ID: 0x{buffer[offset]:02X}")
    offset += 1

    # X/Y coordinates
    x_coord = (buffer[offset] << 8) | buffer[offset + 1]
    offset += 2
    y_coord = (buffer[offset] << 8) | buffer[offset + 1]
    offset += 2
    print(f"📍 X souřadnice: {x_coord}")
    print(f"📍 Y souřadnice: {y_coord}")

    # Part Number (ASCII)
    part_number = ''.join(chr(b) for b in buffer[68:84] if 0x20 <= b <= 0x7E)
    print(f"🧾 Číslo dílu: {part_number}")

    # Batch ID
    print("📦 ID šarže:", "".join(f"{buffer[i]:02X}" for i in range(100, 105)))

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

print_chip_id_struct(payload)
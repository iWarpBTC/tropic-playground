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
    print("🔎 CHIP_ID STRUCT DUMP:")

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

    print()

def analyze_certs(certs):
    """Analyze certificates and print key information"""
    if not certs:
        print("❌ Žádné certifikáty k analýze")
        return
    
    import hashlib
        
    for i, cert in enumerate(certs):
        print(f"\n📜 Certifikát {i+1} ({len(cert)} bajtů):")
        # Print first 16 bytes as hex
        print(f"  Hlavička: {' '.join(f'{b:02X}' for b in cert[:16])}...")
        
        # Calculate fingerprints
        sha1 = hashlib.sha1(cert).hexdigest()
        sha256 = hashlib.sha256(cert).hexdigest()
        print(f"  Fingerprint (SHA1): {':'.join(sha1[j:j+2] for j in range(0, len(sha1), 2))}")
        print(f"  Fingerprint (SHA256): {sha256[:16]}...{sha256[-16:]}")
        
        # Look for common certificate markers
        if len(cert) > 2 and cert[0] == 0x30:
            print(f"  Typ: ASN.1 DER formát")
            
            # Try to find certificate name and other text fields
            found_cn = False
            for j in range(len(cert)-10):
                # Look for CN= (Common Name) in the certificate
                if cert[j:j+3] == b'CN=':
                    end_idx = j+3
                    while end_idx < len(cert) and cert[end_idx] != 0 and cert[end_idx] != 44:  # 44 is comma
                        end_idx += 1
                    cn_value = cert[j:end_idx].decode('ascii', errors='ignore')
                    print(f"  Název: {cn_value}")
                    found_cn = True
                    break
                    
            # If no CN found, look for any text strings
            if not found_cn:
                for j in range(len(cert)-5):
                    if all(32 <= b <= 126 for b in cert[j:j+5]):
                        text_chunk = cert[j:j+min(20, len(cert)-j)].decode('ascii', errors='ignore')
                        print(f"  Text: {text_chunk}...")
                        break
        else:
            print(f"  Typ: Neznámý formát")
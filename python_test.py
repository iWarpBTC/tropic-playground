import serial
import time

import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from l2 import send_frame, get_frame, read_frame, get_resend_response
from utils import print_chip_id_struct, analyze_certs, extract_stpub_from_cert

# === Konfigurace ===
PORT = '/dev/tty.usbmodem141401'  # uprav dle potřeby
BAUDRATE = 115200
TIMEOUT = 2

PROTOCOL_NAME = b"Noise_KK1_25519_AESGCM_SHA256\x00\x00\x00"
   
def get_chip_id(ser: serial.Serial):
    req_data = bytes([0x01, 0x00])
    frame = get_frame(0x01, req_data)
    send_frame(frame, ser)

    payload = read_frame(ser)

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

    print(f"🔢 Verze RISCV firmware: {format_version(payload)}")
    print()

    req_data = bytes([0x04, 0x00])
    frame = get_frame(0x01, req_data)
    send_frame(frame, ser)

    payload = read_frame(ser)

    print(f"🔢 Verze SPECT firmware: {format_version(payload)}")
    print()

def get_certs(ser: serial.Serial):
    req_data = bytes([0x00, 0x00])
    frame = get_frame(0x01, req_data)
    send_frame(frame, ser)

    payload = read_frame(ser)

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

def load_sh0_key():
    """Load SH0 private key and derive public key"""
    #with open('sh0_priv_engineering_sample01.pem', 'rb') as f:
    with open('sh_x25519_private_key_2025-03-24T09-15-15Z.pem', 'rb') as f:
        pem_data = f.read()
    
    # Load the private key from PEM format
    priv_key = load_pem_private_key(pem_data, password=None)
    
    # Derive the public key
    pub_key = priv_key.public_key().public_bytes_raw()
    print(f"🔑 SH0PUB odvozen z privátního klíče: {pub_key.hex()}")
    
    return {
        "private": priv_key,
        "public": pub_key
    }

def make_handshake(ser: serial.Serial, certs=None):
    print()
    print("🔄 Spouštím handshake s TROPIC01...")

    # 1️⃣ Vygeneruj ephemeral X25519 keypair
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes_raw()  # 32 bytů, little-endian

    # 2️⃣ Vyber slot pairing klíče (např. SH0PUB)
    pairing_slot = 0
    req_data = eph_pub + bytes([pairing_slot])

    # 3️⃣ Sestav a pošli handshake rámec
    frame = get_frame(0x02, req_data)
    send_frame(frame, ser)

    # 4️⃣ Zpracuj odpověď
    payload = read_frame(ser)
    if len(payload) != 48:
        raise RuntimeError(f"Handshake response má nečekanou délku: {len(payload)} bajtů")

    e_tpub = payload[:32]
    t_tauth = payload[32:]

    print(f"🔑 TROPIC01 ephemeral public key: {e_tpub.hex()}")
    print(f"🔐 T_TAUTH tag: {t_tauth.hex()}")

    # Load SH0 key and get public key
    sh0_key = load_sh0_key()
    shipub = sh0_key["public"]
    
    # Calculate hash
    h = hashlib.sha256(PROTOCOL_NAME).digest()
    print(f"🔄 h0 = SHA256(protocol_name): {h.hex()}")
    
    # h = SHA256(h||SHiPUB)
    # Using the actual SHiPUB derived from the private key
    h = hashlib.sha256(h + shipub).digest()
    print(f"🔄 h1 = SHA256(h||SHiPUB): {h.hex()}")
    
    # Extract STPUB from the first certificate if available
    stpub = None
    if certs and len(certs) > 0:
        stpub = extract_stpub_from_cert(certs[0])
    else:
        stpub = b''

    # h = SHA256(h||STPUB)
    h = hashlib.sha256(h + stpub).digest()
    print(f"🔄 h2 = SHA256(h||STPUB): {h.hex()}")
    
    # h = SHA256(h||EHPUB)
    h = hashlib.sha256(h + eph_pub).digest()
    print(f"🔄 h3 = SHA256(h||EHPUB): {h.hex()}")
    
    # h = SHA256(h||PKEY_INDEX)
    pkey_index = bytes([pairing_slot])
    h = hashlib.sha256(h + pkey_index).digest()
    print(f"🔄 h4 = SHA256(h||PKEY_INDEX): {h.hex()}")
    
    # h = SHA256(h||ETPUB)
    h = hashlib.sha256(h + e_tpub).digest()
    print(f"🔄 h5 = SHA256(h||ETPUB): {h.hex()}")
    
    # HKDF implementation according to documentation
    def hkdf(ck, input_key, num_outputs):
        import hmac
        
        # tmp = HMAC-SHA256(ck, input)
        tmp = hmac.new(ck, input_key, hashlib.sha256).digest()
        
        # output_1 = HMAC-SHA256(tmp, 0x01)
        output_1 = hmac.new(tmp, bytes([0x01]), hashlib.sha256).digest()
        
        if num_outputs == 1:
            return output_1
        else:
            # output_2 = HMAC-SHA256(tmp, output_1 || 0x02)
            output_2 = hmac.new(tmp, output_1 + bytes([0x02]), hashlib.sha256).digest()
            return (output_1, output_2)
    
    # ck = protocol_name
    ck = PROTOCOL_NAME
    print(f"🔑 Initial ck = protocol_name: {ck.hex()}")
    
    # ck = HKDF(ck, X25519(EHPRIV, ETPUB), 1)
    dh1 = eph_priv.exchange(x25519.X25519PublicKey.from_public_bytes(e_tpub))
    ck = hkdf(ck, dh1, 1)
    print(f"🔑 ck after DH1: {ck.hex()}")
    
    # ck = HKDF(ck, X25519(SHiPRIV, ETPUB), 1)
    dh2 = sh0_key["private"].exchange(x25519.X25519PublicKey.from_public_bytes(e_tpub))
    ck = hkdf(ck, dh2, 1)
    print(f"🔑 ck after DH2: {ck.hex()}")
    
    # ck, k_AUTH = HKDF(ck, X25519(EHPRIV, STPUB), 2)
    if stpub and len(stpub) == 32:  # Make sure STPUB is valid
        try:
            dh3 = eph_priv.exchange(x25519.X25519PublicKey.from_public_bytes(stpub))
            ck, k_auth = hkdf(ck, dh3, 2)
            print(f"🔑 ck after DH3: {ck.hex()}")
            print(f"🔑 k_AUTH: {k_auth.hex()}")
        except Exception as e:
            print(f"❌ Failed to calculate DH3: {e}")
            k_auth = bytes(32)  # Fallback
    else:
        print("❌ Invalid STPUB, using fallback for k_AUTH")
        k_auth = bytes(32)  # Fallback
    
    # k_CMD, k_RES = HKDF(ck, empty string, 2)
    k_cmd, k_res = hkdf(ck, b"", 2)
    print(f"🔑 k_CMD: {k_cmd.hex()}")
    print(f"🔑 k_RES: {k_res.hex()}")
    
    # n = 0
    n = 0
    print(f"🔢 Initial nonce n = {n}")
  
    # Verify T_TAUTH using AES-GCM with k_auth
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    
    # Create zero IV (12 bytes for GCM)
    zero_iv = bytes(12)
    
    # Verify the tag using decryption (as done in the C code)
    try:
        # In AES-GCM, decryption with a valid tag should succeed
        aes_gcm = AESGCM(k_auth)
        # Create empty ciphertext with t_tauth as the tag
        ciphertext_with_tag = b"" + t_tauth
        # Try to decrypt - if successful, the tag is valid
        aes_gcm.decrypt(zero_iv, ciphertext_with_tag, h)
        print("✅ T_TAUTH verification successful!")
    except InvalidTag:
        print("❌ T_TAUTH verification failed: Invalid tag")
        return None  # Return None to indicate failure
    except Exception as e:
        print(f"❌ Error verifying T_TAUTH: {e}")
        return None  # Return None to indicate failureyptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
     
    print(f"🔐 Received T_TAUTH: {t_tauth.hex()} (length: {len(t_tauth)})")
    
    return {
        "k_cmd": k_cmd,
        "k_res": k_res,
        "n": n,
        "h": h
    }


# === Odeslání na Arduino ===
ser = serial.Serial(PORT, BAUDRATE, timeout=TIMEOUT)
time.sleep(2)  # počkej na reset

#get_chip_id(ser)
#get_fw_ver(ser)
certs = get_certs(ser)
#analyze_certs(certs)

result = make_handshake(ser, certs)

def send_l3_ping(ser, secure_obj):
    """Send L3 ping command to TROPIC01"""
    if not secure_obj:
        print("❌ Secure object is None, cannot send L3 ping")
        return
    
    # Prepare the L3 ping frame
    cmd_data = b"Hello, Tropic!"
    cmd_id = 0x01
    to_encrypt = bytes([cmd_id]) + cmd_data
    cmd_size = len(to_encrypt)

    if cmd_size > 252:
        print(f"❌ Příliš velký příkaz: {cmd_size} bajtů (max 255)")
        return
    
    # Encrypt the frame using k_cmd and nonce n
    aes_gcm = AESGCM(secure_obj["k_cmd"])
    
    # Create IV (12 bytes for GCM) from nonce
    init_vec = bytes(8) + secure_obj["n"].to_bytes(4, 'little')
    
    # Encrypt the frame
    encrypted_frame = aes_gcm.encrypt(init_vec, to_encrypt, b'')
    # Tamper with the tag
#    encrypted_frame = encrypted_frame[:-1] + bytes([encrypted_frame[-1] ^ 0x01])
    l3_frame = cmd_size.to_bytes(2, 'little') + encrypted_frame

    # prepare l2 frame
    l2_frame = get_frame(0x04, l3_frame)

    # Send the encrypted frame
    send_frame(l2_frame, ser)
    
    print()
    print("📤 L3 ping sent successfully")


def send_l3_rnd(ser, secure_obj):
    """Send L3 random command to TROPIC01"""
    if not secure_obj:
        print("❌ Secure object is None, cannot send L3 random")
        return
    
    # Prepare the L3 random frame
    cmd_data = bytes([0x01]) 
    cmd_id = 0x50
    to_encrypt = bytes([cmd_id]) + cmd_data
    cmd_size = len(to_encrypt)
    
    # Encrypt the frame using k_cmd and nonce n
    aes_gcm = AESGCM(secure_obj["k_cmd"])
    
    # Create IV (12 bytes for GCM) from nonce
    init_vec = bytes(8) + secure_obj["n"].to_bytes(4, 'little')
    
    # Encrypt the frame
    encrypted_frame = aes_gcm.encrypt(init_vec, to_encrypt, b'')
    
    l3_frame = cmd_size.to_bytes(2, 'little') + encrypted_frame

    # prepare l2 frame
    l2_frame = get_frame(0x04, l3_frame)

    # Send the encrypted frame
    send_frame(l2_frame, ser)
    
    print("📤 L3 random sent successfully")

def trigger_get_response(ser):
    """Trigger a response from TROPIC01"""
    print("🔄 Odesílám trigger pro získání odpovědi...")
    full_frame = [0xA5, 0x00]

    ser.write(full_frame)

send_l3_ping(ser, result)
response = read_frame(ser)

trigger_get_response(ser) # dunno why this is needed
response = read_frame(ser)
print("\n📥 Odpověď z TROPIC01:")
print(" ".join(f"{b:02X}" for b in response))

res_size = response[0] | (response[1] << 8)
ciphertext = response[2:]

aes_gcm = AESGCM(result["k_res"])
init_vec = bytes(8) + result["n"].to_bytes(4, 'little')
decrypted = aes_gcm.decrypt(init_vec, ciphertext, b'')
print(f"🔓 Rozšifrovaná response: {decrypted.hex()}")
# interpret the decrypted response as ASCII
print(f"🔓 Rozšifrovaná response (ASCII): {decrypted.decode('ascii', errors='ignore')}")
print()
print()
    
result["n"] += 1  # Increment nonce for next command
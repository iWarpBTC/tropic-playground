import serial
import time
import base64

import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from crc import add_crc, calc_crc
from utils import print_chip_id_struct, analyze_certs, extract_stpub_from_cert

# === Konfigurace ===
PORT = '/dev/tty.usbmodem141401'  # uprav dle potřeby
BAUDRATE = 115200
TIMEOUT = 2
DEBUG = True

PROTOCOL_NAME = b"Noise_KK1_25519_AESGCM_SHA256\x00\x00\x00"

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

def load_sh0_key():
    """Load SH0 private key and derive public key"""
    #with open('sh0_priv_engineering_sample01.pem', 'rb') as f:
    with open('sh_x25519_private_key_2025-03-24T09-15-15Z.pem', 'rb') as f:
        pem_data = f.read()
    
    # Load the private key from PEM format
    priv_key = load_pem_private_key(pem_data, password=None)
    
    # Derive the public key
    pub_key = priv_key.public_key().public_bytes_raw()
    print(f"🔑 SH0PUB derived from private key: {pub_key.hex()}")
    
    return {
        "private": priv_key,
        "public": pub_key
    }

def make_handshake(ser: serial.Serial, certs=None):
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
    
    '''    # 5️⃣ Odvoď shared secret
    shared_secret = dh1  # This is the same as eph_priv.exchange(x25519.X25519PublicKey.from_public_bytes(e_tpub))
    print(f"🧩 Sdílený tajný klíč: {shared_secret.hex()}")
    '''

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
    
    # Debug: Try different approaches to see what works
    print("\n🔧 DEBUGGING T_TAUTH VERIFICATION:")
    
    # Approach 1: Standard AESGCM with zero IV
    try:
        zero_iv = bytes(12)  # 12 bytes for GCM
        aes_gcm = AESGCM(k_auth)
        tag1 = aes_gcm.encrypt(zero_iv, b"", h)  # Empty plaintext, just get the tag
        print(f"1️⃣ AESGCM with zero IV (12 bytes): {tag1.hex()}")
    except Exception as e:
        print(f"1️⃣ Error: {e}")
    
    # Approach 2: Try with 16-byte zero IV
    try:
        zero_iv_16 = bytes(16)
        aes_gcm = AESGCM(k_auth)
        tag2 = aes_gcm.encrypt(zero_iv_16, b"", h)
        print(f"2️⃣ AESGCM with zero IV (16 bytes): {tag2.hex()}")
    except Exception as e:
        print(f"2️⃣ Error: {e}")
    
    # Approach 3: Try with AES-GCM manually constructed
    try:
        zero_iv_16 = bytes(16)
        encryptor = Cipher(algorithms.AES(k_auth), modes.GCM(zero_iv_16)).encryptor()
        encryptor.authenticate_additional_data(h)
        encryptor.update(b"")
        encryptor.finalize()
        tag3 = encryptor.tag
        print(f"3️⃣ Manual AES-GCM with zero IV (16 bytes): {tag3.hex()}")
    except Exception as e:
        print(f"3️⃣ Error: {e}")
    
    # Approach 4: Try with different hash value (h4 instead of h5)
    try:
        h4 = hashlib.sha256(h + pkey_index).digest()  # This is h4 from earlier
        aes_gcm = AESGCM(k_auth)
        tag4 = aes_gcm.encrypt(zero_iv, b"", h4)
        print(f"4️⃣ AESGCM with h4 instead of h5: {tag4.hex()}")
    except Exception as e:
        print(f"4️⃣ Error: {e}")
    
    # Approach 5: Try with truncated tag (first 16 bytes)
    try:
        aes_gcm = AESGCM(k_auth)
        full_tag = aes_gcm.encrypt(zero_iv, b"", h)
        tag5 = full_tag[:16]  # Take only first 16 bytes
        print(f"5️⃣ AESGCM with truncated tag (16 bytes): {tag5.hex()}")
        if tag5 == t_tauth:
            print("✅ Match found with truncated tag!")
    except Exception as e:
        print(f"5️⃣ Error: {e}")
        
    # Approach 6: Try with the original HKDF implementation
    try:
        def original_hkdf(ck, input_key, num_outputs):
            import hmac
            temp_key = hmac.new(ck, input_key, hashlib.sha256).digest()
            outputs = []
            for i in range(1, num_outputs + 1):
                outputs.append(hmac.new(temp_key, bytes([i]), hashlib.sha256).digest())
            return outputs[0] if num_outputs == 1 else outputs
            
        # Recalculate keys with original HKDF
        orig_ck = PROTOCOL_NAME
        orig_ck = original_hkdf(orig_ck, dh1, 1)
        orig_ck = original_hkdf(orig_ck, dh2, 1)
        orig_ck, orig_k_auth = original_hkdf(orig_ck, dh3, 2)
        
        print(f"6️⃣ Original k_AUTH: {orig_k_auth.hex()}")
        
        # Try verification with original k_auth
        aes_gcm = AESGCM(orig_k_auth)
        tag6 = aes_gcm.encrypt(zero_iv, b"", h)[:16]  # Use truncated tag
        print(f"6️⃣ AESGCM with original HKDF: {tag6.hex()}")
        if tag6 == t_tauth:
            print("✅ Match found with original HKDF implementation!")
    except Exception as e:
        print(f"6️⃣ Error: {e}")
        
    # Approach 7: Try with C implementation style
    try:
        # Based on the C code in lt_l3.c
        # lt_hkdf(protocol_name, 32, shared_secret, 32, 1, output_1, output_2);
        def c_style_hkdf(ck, dh_out, num_outputs):
            import hmac
            
            # First output
            output_1 = hmac.new(ck, dh_out, hashlib.sha256).digest()
            
            if num_outputs == 1:
                return output_1, None
            else:
                # Second output
                output_2 = hmac.new(ck, output_1, hashlib.sha256).digest()
                return output_1, output_2
        
        # Recalculate keys with C-style HKDF
        c_ck, _ = c_style_hkdf(PROTOCOL_NAME, dh1, 1)
        c_ck, _ = c_style_hkdf(c_ck, dh2, 1)
        c_ck, c_k_auth = c_style_hkdf(c_ck, dh3, 2)
        c_k_cmd, c_k_res = c_style_hkdf(c_ck, b"", 2)
        
        print(f"7️⃣ C-style k_AUTH: {c_k_auth.hex()}")
        
        # Try verification with C-style k_auth
        aes_gcm = AESGCM(c_k_auth)
        tag7 = aes_gcm.encrypt(zero_iv, b"", h)[:16]  # Use truncated tag
        print(f"7️⃣ AESGCM with C-style HKDF: {tag7.hex()}")
        if tag7 == t_tauth:
            print("✅ Match found with C-style HKDF implementation!")
    except Exception as e:
        print(f"7️⃣ Error: {e}")
        
    # Approach 8: Try decryption instead of encryption
    # In the C code: ret = lt_aesgcm_decrypt(&h->l3.decrypt, h->l3.decryption_IV, 12u, hash, 32, (uint8_t *)"", 0, p_rsp->t_tauth, 16u);
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        
        # Try with all our key variations
        keys_to_try = [
            ("Standard", k_auth),
            ("Original", orig_k_auth),
            ("C-style", c_k_auth)
        ]
        
        for key_name, key in keys_to_try:
            try:
                # In AES-GCM, decryption with a valid tag should succeed
                # The tag is appended to the ciphertext in the cryptography library
                aes_gcm = AESGCM(key)
                # Create empty ciphertext with t_tauth as the tag
                ciphertext_with_tag = b"" + t_tauth
                # Try to decrypt - if successful, the tag is valid
                result = aes_gcm.decrypt(zero_iv, ciphertext_with_tag, h)
                print(f"8️⃣ {key_name} key: Decryption successful! Tag is valid.")
                print("✅ Match found with decryption approach!")
            except InvalidTag:
                print(f"8️⃣ {key_name} key: Invalid tag")
            except Exception as e:
                print(f"8️⃣ {key_name} key error: {e}")
    except Exception as e:
        print(f"8️⃣ Error: {e}")
    
    print(f"🔐 Received T_TAUTH: {t_tauth.hex()} (length: {len(t_tauth)})")
    
    # Compare with received tag
    if t_tauth in [tag1, tag2, tag3, tag4, tag5, tag6, tag7] or "Match found" in locals():
        print("✅ T_TAUTH verification successful with one of the approaches!")
    else:
        print("❌ T_TAUTH verification failed with all approaches")
    
    return {
        "eph_priv": eph_priv,
        "eph_pub": eph_pub,
        "chip_ephemeral_pub": e_tpub,
        "t_auth_tag": t_tauth,
        "k_auth": k_auth,
        "k_cmd": k_cmd,
        "k_res": k_res,
        "n": n
    }


# === Odeslání na Arduino ===
ser = serial.Serial(PORT, BAUDRATE, timeout=TIMEOUT)
time.sleep(2)  # počkej na reset

#get_chip_id(ser)
#get_fw_ver(ser)
certs = get_certs(ser)
#analyze_certs(certs)

result = make_handshake(ser, certs)

'''
def derive_session_keys(shared_secret: bytes):
    import hmac

    # === Reimplementace přesně dle lt_hkdf.c ===
    tmp = hmac.new(shared_secret, shared_secret, hashlib.sha256).digest()  # první HMAC
    k_enc = hmac.new(tmp, b'\x01', hashlib.sha256).digest()                # druhý HMAC (výstup 1)

    helper = k_enc + b'\x02'
    k_mac = hmac.new(tmp, helper, hashlib.sha256).digest()                # třetí HMAC (výstup 2)

    return {"k_enc": k_enc, "k_mac": k_mac}

def send_l3_ping(ser, session_keys):
    import os
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hmac, hashes

    data_in = b"Hello, Tropic!"
    l3_inner = bytes([0x01, len(data_in)]) + data_in

    nonce = os.urandom(16)
    aes = Cipher(algorithms.AES(session_keys["k_enc"]), modes.CTR(nonce[:16])).encryptor()
    ciphertext = aes.update(l3_inner) + aes.finalize()

    mac = hmac.HMAC(session_keys["k_mac"], hashes.SHA256())
    mac.update(nonce + ciphertext)
    tag = mac.finalize()

    l3_payload = nonce + ciphertext + tag
    if len(l3_payload) > 255:
        raise ValueError(f"L3 payload je příliš dlouhý: {len(l3_payload)} bajtů (max 255)")
    cmd_len = len(l3_payload)
    if cmd_len != len(l3_payload):
        raise ValueError(f"CMD_LEN neodpovídá skutečné délce dat ({cmd_len} vs {len(l3_payload)})")
    l2_req_data = bytes([0x01, cmd_len]) + l3_payload
    frame = get_frame(0x04, l2_req_data)
    send_frame(frame, ser)

    payload = read_frame(ser)
    if DEBUG:
        print("\n📥 Odpověď na L3 PING:")
        print(" ".join(f"{b:02X}" for b in payload))

keys = derive_session_keys(result["shared_secret"])
send_l3_ping(ser, keys)
'''
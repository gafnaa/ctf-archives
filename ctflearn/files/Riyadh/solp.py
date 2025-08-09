import struct

def to_bytes(n, length=8):
    """Converts an integer to a little-endian byte string."""
    try:
        return n.to_bytes(length, 'little')
    except OverflowError:
        # Handle signed integers by converting them to unsigned
        return (n & ((1 << length * 8) - 1)).to_bytes(length, 'little')

def xor_bytes(b1, b2):
    """XORs two byte strings."""
    return bytes(x ^ y for x, y in zip(b1, b2))

# --- Data extracted from the decompiler output ---

# XOR Mask data block (starts at xormask, 0x4160)
xormask_data = {
    'xormask': 5438854655020910234,      # 0x4160
    'qword_4168': -1579607123670352383, # 0x4168
    'qword_4170': 6625438212951092519,  # 0x4170
    'qword_4178': -1801001522652020996, # 0x4178
    'qword_4180': 1304284945428489509,  # 0x4180
    'qword_4188': -7374316202711988518, # 0x4188
    'byte_4190': ord('-'),
    'byte_4191': ord('A'),
    'byte_4192': 0xBD,
    'byte_4193': 0x9D,
}

# Combine mask data into a single byte string for easier slicing
mask = b"".join([
    to_bytes(xormask_data['xormask']),
    to_bytes(xormask_data['qword_4168']),
    to_bytes(xormask_data['qword_4170']),
    to_bytes(xormask_data['qword_4178']),
    to_bytes(xormask_data['qword_4180']),
    to_bytes(xormask_data['qword_4188']),
    to_bytes(xormask_data['byte_4190'], 1),
    to_bytes(xormask_data['byte_4191'], 1),
    to_bytes(xormask_data['byte_4192'], 1),
    to_bytes(xormask_data['byte_4193'], 1),
])

# Encrypted data blocks for each message
encrypted_data = {
    "Msg1 (Welcome)": [
        7719130253836952525,   # wmsg
        -8108627891223015051,  # qword_4128
        4218502454495534918,   # qword_4130
        -7681741504762407272,  # qword_4138
        8318574156925488214,   # qword_4140
        -7383564609852757322,  # qword_4148
    ],
    "Msg2 (Usage)": [
        1826925548927006159,   # umsg
        -8758872523018156184,  # qword_4108
        -13754,                # word_4110 (2 bytes)
        ord('?'),              # byte_4112 (1 byte)
    ],
    "Msg3 (Password prompt)": [
        2668611595709846233,   # ffmsg
        -8978090964923519878,  # qword_40E8
        4230876217041013321,   # qword_40F0
        1935,                  # word_40F8 (2 bytes)
        0x1E,                  # byte_40FA (1 byte)
        ord('B'),              # byte_40FB (1 byte)
    ],
    "Msg4 (Decoy Success)": [
        2670597299552725443,   # fffmsg
        -8398584565781258651,  # qword_40A8
        4364872689380941387,   # qword_40B0
        -4075007950270013731,  # qword_40B8
        7383836631202253387,   # qword_40C0
        -1383438492053232646,  # qword_40C8
        ord('I'), ord('$'), 0x9C, 0x9D # bytes 40D0-40D3
    ],
    "Msg5 (THE FLAG!)": [
        2668611595709846233,   # fmsg
        -5368437137445031046,  # qword_4078
        2918664069484233313,   # qword_4080
        1952141219,            # dword_4088 (4 bytes)
        -3171,                 # word_408C (2 bytes)
        0x01,                  # byte_408E (1 byte)
    ],
    "Msg6 (Failure)": [
        3318835283313895875,   # bfmsg
        -3859176117670257805,  # qword_4058
        4004940957569048400,   # qword_4060
        2017663389,            # dword_4068 (4 bytes)
        -22907,                # word_406C (2 bytes)
        0x01,                  # byte_406E (1 byte)
    ],
    "Msg7 (Success)": [
        2174939743292099033,   # conmsg
        -3798973203105710259,  # qword_4028
        3788768115343920390,   # qword_4030
        -4078881528279002999,  # qword_4038
        1028049219,            # dword_4040 (4 bytes)
        -8187,                 # word_4044 (2 bytes)
        0x19,                  # byte_4046 (1 byte)
    ]
}

def decrypt_message(encrypted_parts):
    """Decrypts a message by XORing its parts with the mask."""
    encrypted_bytes = b""
    for part in encrypted_parts:
        if isinstance(part, int):
            if -32768 <= part <= 32767: # Likely word_xxxx (2 bytes)
                encrypted_bytes += to_bytes(part, 2)
            elif -2147483648 <= part <= 2147483647: # Likely dword_xxxx (4 bytes)
                encrypted_bytes += to_bytes(part, 4)
            else: # Likely qword_xxxx (8 bytes)
                encrypted_bytes += to_bytes(part, 8)
        else: # Likely single byte
            encrypted_bytes += to_bytes(part, 1)

    decrypted = xor_bytes(mask, encrypted_bytes)
    # Return as a string, removing null terminators
    return decrypted.split(b'\x00')[0].decode('utf-8', errors='ignore')

# --- Decrypt and Print All Messages ---
print("--- Decrypted Messages ---\n")
for name, data in encrypted_data.items():
    decrypted_msg = decrypt_message(data)
    print(f"{name}:\n> {decrypted_msg}\n")

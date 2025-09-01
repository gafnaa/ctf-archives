OPS_SEQUENCE = [
    "j3s5l", "j3s5l", "m9kp2", "qwx7z", "qwx7z", "m9kp2", "j3s5l", "j3s5l",
    "qwx7z", "j3s5l", "j3s5l", "qwx7z", "m9kp2", "j3s5l", "qwx7z", "j3s5l",
    "m9kp2", "j3s5l", "j3s5l", "m9kp2", "m9kp2", "qwx7z", "j3s5l", "m9kp2",
    "j3s5l", "m9kp2", "m9kp2", "j3s5l", "m9kp2", "qwx7z", "qwx7z", "qwx7z",
    "qwx7z"
]

KEY = [
    143, 193, 38, 93, 97, 13, 149, 22, 102, 163, 38, 84, 55, 157, 130, 12,
    65, 133, 194, 3, 9, 162, 198, 41, 77, 20, 55, 76, 17, 192, 207, 104, 163
]

ENCRYPTED_DATA = [
    200, 132, 39, 158, 180, 71, 220, 93, 151, 155, 93, 185, 67, 194, 245, 111,
    49, 236, 178, 113, 96, 272, 161, 54, 33, 77, 55, 43, 100, 289, 310, 205, 288
]

def inv_xor(ct_byte, key_byte):
    return (ct_byte & 0xFF) ^ key_byte

def inv_sub(ct_byte, key_byte):
    return ((ct_byte & 0xFF) + key_byte) & 0xFF

def inv_add(ct_byte, key_byte):
    return ((ct_byte & 0xFF) - key_byte) & 0xFF

def decrypt_flag():
    if not (len(OPS_SEQUENCE) == len(KEY) == len(ENCRYPTED_DATA)):
        print("Error: Data arrays must have the same length.")
        return

    decrypted_chars = []
    for i in range(len(OPS_SEQUENCE)):
        op_name = OPS_SEQUENCE[i]
        key_val = KEY[i]
        ct_val = ENCRYPTED_DATA[i]

        decrypted_byte = 0
        if op_name == "j3s5l": 
            decrypted_byte = inv_xor(ct_val, key_val)
        elif op_name == "m9kp2": 
            decrypted_byte = inv_sub(ct_val, key_val)
        elif op_name == "qwx7z": 
            decrypted_byte = inv_add(ct_val, key_val)
        else:
            print(f"Unknown operation at index {i}: {op_name}")
            return
            
        decrypted_chars.append(chr(decrypted_byte))

    flag = "".join(decrypted_chars)
    print(f"Decrypted Flag: {flag.strip()}")

if __name__ == "__main__":
    decrypt_flag()


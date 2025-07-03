def xor_string_with_13(s):
    result = ''
    for char in s:
        xored = ord(char) ^ 13  # XOR tiap karakter dengan 13
        result += chr(xored)    # Konversi kembali ke karakter
    return result

label = "label"  # Ganti ini jika nilai label berbeda
decoded = xor_string_with_13(label)
flag = f"crypto{{{decoded}}}"

print(flag)

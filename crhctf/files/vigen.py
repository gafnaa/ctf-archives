import string

def vigenere_decrypt(ciphertext, key):
    alphabet = string.ascii_uppercase
    decrypted = []
    key = key.upper()
    ki = 0
    for c in ciphertext:
        if c.upper() in alphabet:
            shift = alphabet.index(key[ki % len(key)])
            dec = (alphabet.index(c.upper()) - shift) % 26
            new_c = alphabet[dec]
            if c.islower():
                new_c = new_c.lower()
            decrypted.append(new_c)
            ki += 1
        else:
            decrypted.append(c)
    return "".join(decrypted)

ciphertext = "ILYC{gg_z_a_mifd_ybrrq}"

# plaintext harusnya diawali CRHC{
known_plain = "CRHC{"
partial_ct = ciphertext[:len(known_plain)]

alphabet = string.ascii_uppercase
key = []

for c, p in zip(partial_ct, known_plain):
    if c.upper() in alphabet and p.upper() in alphabet:
        k = (alphabet.index(c.upper()) - alphabet.index(p.upper())) % 26
        key.append(alphabet[k])

key = "".join(key)
print("Derived partial key:", key)

# coba decrypt dengan key ini (diulang sepanjang teks)
plaintext = vigenere_decrypt(ciphertext, key)
print("Decrypted:", plaintext)

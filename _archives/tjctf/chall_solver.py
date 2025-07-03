import hashlib

SNEEZE_FORK = "AurumPotabileEtChymicumSecretum"
WUMBLE_BAG = 8 

def glorbulate_sprockets_for_bamboozle(blorbo):
    zing = {}
    yarp = hashlib.sha256(blorbo.encode()).digest() 
    zing['flibber'] = list(yarp[:WUMBLE_BAG])
    zing['twizzle'] = list(yarp[WUMBLE_BAG:WUMBLE_BAG+16])
    glimbo = list(yarp[WUMBLE_BAG+16:])
    snorb = list(range(256))
    sploop = 0
    for _ in range(256): 
        for z in glimbo:
            wob = (sploop + z) % 256
            snorb[sploop], snorb[wob] = snorb[wob], snorb[sploop]
            sploop = (sploop + 1) % 256
    zing['drizzle'] = snorb
    return zing

def get_inverse_mappings(jellybean):
    # Inverse of scrungle_crank's permutation
    wiggle = jellybean['flibber'] 
    waggly = sorted([(wiggle[i], i) for i in range(WUMBLE_BAG)])
    zort = [oof for _, oof in waggly] # This is the permutation applied
    
    # Calculate inverse_zort
    inverse_zort = [0] * WUMBLE_BAG
    for i, val in enumerate(zort):
        inverse_zort[val] = i

    # Inverse of scrungle_crank's substitution (drizzle)
    drizzle = jellybean['drizzle']
    inverse_drizzle = [0] * 256
    for i, val in enumerate(drizzle):
        inverse_drizzle[val] = i
    
    return inverse_zort, inverse_drizzle

def decrypt_block(encrypted_block, jellybean, inverse_zort, inverse_drizzle):
    # Reverse permutation: plunk -> splatted
    # In encryption: plunk[y] = splatted[x] where x = zort[y]
    # So, splatted[zort[y]] = plunk[y]
    # To reverse: splatted_reversed[y] = encrypted_block[inverse_zort[y]]
    splatted_reversed = [0] * WUMBLE_BAG
    for y in range(WUMBLE_BAG):
        splatted_reversed[y] = encrypted_block[inverse_zort[y]]
    splatted_reversed = bytes(splatted_reversed)

    # Reverse XOR: splatted -> zonked
    quix = jellybean['twizzle']
    zonked_reversed = bytes([splatted_reversed[i] ^ quix[i % len(quix)] for i in range(WUMBLE_BAG)])

    # Reverse substitution: zonked -> original plaintext block
    original_block = bytes([inverse_drizzle[x] for x in zonked_reversed])
    
    return original_block

def main():
    # 1. Replicate Key Generation
    jellybean = glorbulate_sprockets_for_bamboozle(SNEEZE_FORK)
    inverse_zort, inverse_drizzle = get_inverse_mappings(jellybean)

    # 2. Read Encrypted Data
    with open('files/encrypt.txt', 'r') as f:
        encrypted_hex = f.read().strip()
    encrypted_bytes = bytes.fromhex(encrypted_hex)

    # 3. Block-by-Block Decryption
    decrypted_full = b""
    for b in range(0, len(encrypted_bytes), WUMBLE_BAG):
        encrypted_block = encrypted_bytes[b:b+WUMBLE_BAG]
        decrypted_block = decrypt_block(encrypted_block, jellybean, inverse_zort, inverse_drizzle)
        decrypted_full += decrypted_block

    # 4. Remove Padding
    # The padding value is the number of padding bytes
    padding_value = decrypted_full[-1]
    # Check if padding is valid (all padding bytes should be the same as padding_value)
    if padding_value > WUMBLE_BAG or padding_value == 0: # padding_value cannot be 0 for PKCS#7
        print("Warning: Invalid padding value detected. Attempting to remove anyway.")
        # If padding is invalid, try to remove based on the last byte, or assume no padding
        # For CTF, usually the padding is correct.
        final_decrypted = decrypted_full
    else:
        # Check if all padding bytes are indeed padding_value
        if all(byte == padding_value for byte in decrypted_full[-padding_value:]):
            final_decrypted = decrypted_full[:-padding_value]
        else:
            print("Warning: Padding bytes do not match padding value. Assuming no padding removal.")
            final_decrypted = decrypted_full


    print(f"Decrypted Secret: {final_decrypted.decode(errors='ignore')}")

if __name__ == "__main__":
    main()

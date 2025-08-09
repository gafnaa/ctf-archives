import base64

def decode_vba_string():
    """
    This script deobfuscates a multi-layered Base64 string
    found in a VBA macro.
    """
    # Character codes extracted from the VBA macro for each variable
    satu = [84, 71, 57, 121, 90, 87, 48, 103, 83, 88, 66, 122, 100, 87, 48, 103, 97, 88, 77, 103, 99, 50, 108, 116, 99, 71, 120, 53, 73, 71, 82, 49, 98, 87, 49, 53, 73, 72, 82, 108, 101, 72, 81, 103, 98, 50, 89, 103, 100, 71, 104, 108, 73, 72, 66, 121, 97, 87, 53, 48, 97, 87]
    dua = [53, 110, 73, 71, 70, 117, 90, 67, 66, 48, 101, 88, 66, 108, 99, 50, 86, 48, 100, 71, 108, 117, 90, 121, 66, 112, 98, 109, 82, 49, 99, 51, 82, 121, 101, 83, 52, 103, 84, 71, 57, 121, 90, 87, 48, 103, 83, 88, 66, 122, 100, 87, 48, 103, 97, 71, 70, 122, 73, 71, 74, 108, 90, 87, 52, 103, 100, 71, 104, 108, 73, 71, 108, 117, 90, 72, 86, 122, 100, 72, 74, 53, 74, 51, 77, 103]
    tiga = [99, 51, 82, 104, 98, 109, 82, 104, 99, 109, 81, 103, 90, 72, 86, 116, 98, 88, 107, 103, 100, 71, 86, 52, 100, 67, 66, 108, 100, 109, 86, 121, 73, 72, 78, 112, 98, 109, 78, 108, 73, 72, 82, 111, 90, 83, 66, 111, 100, 72, 82, 119, 99, 122, 111, 118, 76, 51, 66, 104, 99, 51, 82, 108, 89, 109, 108, 117, 76, 109, 78, 118, 98]
    empat = [83, 56, 53, 89, 87, 53, 122, 81, 107, 120, 90, 83, 121, 66, 105, 100, 88, 81, 103, 89, 87, 120, 122, 98, 121, 66, 48, 97, 71, 85, 103, 98, 71, 86, 104, 99, 67, 66, 112, 98, 110, 82, 118, 73, 71, 86, 115, 90, 87, 78, 48, 99, 109, 57, 117, 97, 87, 77, 103, 100, 72, 108, 119, 90, 88, 78, 108, 100, 72, 82, 112, 98, 109, 99, 115, 73, 72, 74, 108, 98, 87, 70, 112, 98, 109]
    lima = [108, 117, 90, 121, 66, 108, 99, 51, 78, 108, 98, 110, 82, 112, 89, 87, 120, 115, 101, 83, 66, 49, 98, 109, 78, 111, 89, 87, 53, 110, 90, 87, 81, 117, 73, 69, 108, 48, 73, 72, 100, 104, 99, 121, 66, 119, 98, 51, 66, 49, 98, 71, 70, 121, 97, 88, 78, 108, 90, 67, 66, 112, 98, 105, 66, 48, 97, 71, 85, 103, 77, 84, 107, 50, 77, 72, 77, 103, 100, 50, 108, 48, 97]
    enam = [67, 66, 48, 97, 71, 85, 103, 99, 109, 86, 115, 90, 87, 70, 122, 90, 83, 66, 118, 90, 105, 66, 77, 90, 88, 82, 121, 89, 88, 78, 108, 100, 67, 66, 122, 97, 71, 86, 108, 100, 72, 77, 103, 89, 50, 57, 117, 100, 71, 70, 112, 98, 109, 108, 117, 90, 119, 61, 61]

    # Combine all character codes into a single list
    all_codes = satu + dua + tiga + empat + lima + enam

    # Convert the list of codes into a string
    encoded_string = "".join(chr(code) for code in all_codes)
    
    print("--- Decryption Process ---")
    print(f"Initial concatenated string (first layer of Base64):\n{encoded_string}\n")

    # Repeatedly decode the string from Base64 until it's no longer Base64
    decoded_payload = encoded_string
    layer = 1
    while True:
        try:
            # Add padding if necessary, as some layers might be missing it
            missing_padding = len(decoded_payload) % 4
            if missing_padding:
                decoded_payload += '=' * (4 - missing_padding)
            
            # Decode from bytes to string for the next potential decoding round
            decoded_payload = base64.b64decode(decoded_payload).decode('utf-8')
            print(f"--- After Base64 Decode Layer {layer} ---\n{decoded_payload}\n")
            layer += 1
        except (base64.binascii.Error, UnicodeDecodeError):
            # If it's not valid Base64 or can't be decoded to UTF-8, we're done
            print("--- Final Decrypted Payload ---")
            # The last successful decode is our final payload
            # We need to go back one step as the loop exits on failure
            final_payload = base64.b64decode(encoded_string)
            for _ in range(layer - 2):
                 final_payload = base64.b64decode(final_payload)
            
            print(final_payload.decode('utf-8', errors='ignore'))
            break

if __name__ == "__main__":
    decode_vba_string()

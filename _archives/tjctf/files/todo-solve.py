# A script to solve repeating-key XOR ciphers

# The ciphertext from your TODO list challenge
ciphertext_arrays = [
    [108, 67, 82, 10, 77, 70, 67, 94, 73, 66, 79, 89],
    [107, 78, 92, 79, 88, 94, 67, 89, 79, 10, 73, 69, 71, 90, 75, 68, 83],
    [105, 88, 79, 75, 94, 79, 10, 8, 72, 95, 89, 67, 68, 79, 89, 89, 117, 89, 79, 73, 88, 79, 94, 89, 8, 10, 90, 75, 77, 79, 10, 7, 7, 10, 71, 75, 78, 79, 10, 67, 94, 10, 72, 95, 94, 10, 68, 69, 10, 72, 95, 94, 94, 69, 68, 10, 94, 69, 10, 75, 73, 73, 79, 89, 89, 10, 83, 79, 94],
    [126, 75, 65, 79, 10, 69, 92, 79, 88, 10, 94, 66, 79, 10, 93, 69, 88, 70, 78, 10, 7, 7, 10, 75, 70, 71, 69, 89, 94, 10, 78, 69, 68, 79]
]

# Combine all numbers into a single list
full_ciphertext = [num for arr in ciphertext_arrays for num in arr]

# A scoring function to determine how "English-like" a text is.
# Higher scores are better.
def score_english_text(text_bytes):
    score = 0
    # Frequencies of common English letters (and space)
    # from http://en.algoritmy.net/article/40379/character-frequencies
    freq = {
        'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
        'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
        'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
        'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
        'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
        'z': 0.074, ' ': 13.000
    }
    for byte in text_bytes:
        char = chr(byte).lower()
        if char in freq:
            score += freq[char]
        # Penalize non-printable or weird characters
        elif byte < 32 or byte > 126:
            score -= 20
    return score

def break_repeating_key_xor(ciphertext):
    best_guess = {'key': '', 'plaintext': '', 'score': 0}

    # Iterate through likely key lengths
    for key_length in range(3, 16):
        
        potential_key = []
        # Solve for each byte of the key
        for i in range(key_length):
            # Get all ciphertext bytes that were XORed with this key byte
            column = ciphertext[i::key_length]
            
            best_key_byte = 0
            highest_score = -1
            
            # Brute-force the single key byte for this column
            for k in range(256):
                decrypted_column = bytes([b ^ k for b in column])
                current_score = score_english_text(decrypted_column)
                
                if current_score > highest_score:
                    highest_score = current_score
                    best_key_byte = k
            
            potential_key.append(best_key_byte)

        # Now, decrypt the whole text with the potential key and score it
        key_bytes = bytes(potential_key)
        plaintext_bytes = bytes([ciphertext[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(ciphertext))])
        total_score = score_english_text(plaintext_bytes)

        print(f"Trying key length {key_length}... Found key: {key_bytes.decode(errors='ignore')}, Score: {total_score:.2f}")

        if total_score > best_guess['score']:
            best_guess['score'] = total_score
            best_guess['key'] = key_bytes
            best_guess['plaintext'] = plaintext_bytes

    return best_guess


# Run the solver
solution = break_repeating_key_xor(full_ciphertext)

print("\n" + "="*50)
print("      >>> SOLUTION FOUND <<<")
print("="*50)
print(f"Best Key Found: {solution['key'].decode(errors='ignore')}")
print(f"Highest Score: {solution['score']:.2f}")
print("\n--- DECRYPTED TODO LIST ---")

# Print the decoded text, re-inserting newlines where the number 10 (XORed) was
# The number 10 XORed with the corresponding key byte will produce a newline
# We can just print the full plaintext for simplicity here.
print(solution['plaintext'].decode(errors='ignore'))
print("---------------------------\n")
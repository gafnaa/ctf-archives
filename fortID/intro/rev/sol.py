def decrypt_flag():
    """
    Decrypts a flag that was encrypted using a binary search algorithm.
    The encrypted string represents the steps (<, >, =) of the binary search
    for each character of the original flag.
    """
    # The hardcoded string from the binary that we need to decrypt.
    encrypted_string = "<><<<>>=<>>=<>>><<>=<>>><><=<><<><=<><<<><=<>>>>=<<>><=<>><<<=<<>>=<>=<><>><=<<>><<<=<>>><>=<>>><<>=<>=<><><>>=<<>><=<>><=<>><=<<>><<=<>><<>=<<>><>=<>=<<>><><=<>><>>>=<>><<><=<>=<><<>><=<<>><=<>>><<>=<>><>>>=<>=<><>><=<<>><<<=<>>><>=<>>><<>=<>=<><<<>>=<>>><>=<>><>>>=<>><<><=<<>><><=<>><>>=<<>><=<>><>>>=<<>>=<<>><><=<<>><<=<>=<><><=<<>><=<>><<<=<>>><<>=<>><<=<>><><<=<>=<><<<<=<>><>><=<>><=<<>><<<=<>>><<>=<<>><<=<<>>=<>><><<=<>><>>=<<>><>=<>>>>>="

    print("Decrypting the flag...")

    # Initialize the search range for ASCII values (0-255).
    low = 0
    high = 255
    
    decrypted_chars = []

    # Iterate through the encrypted string to decode each character.
    for operation in encrypted_string:
        # Calculate the midpoint of the current range using integer division.
        mid = low + (high - low) // 2

        if operation == '<':
            # If the character was less than or equal to the guess,
            # the upper bound of the search was lowered.
            high = mid - 1
        elif operation == '>':
            # If the character was greater than the guess,
            # the lower bound of the search was raised.
            low = mid + 1
        elif operation == '=':
            # An '=' signifies that the correct character has been found.
            # The value of 'mid' at this point is the ASCII code.
            decrypted_chars.append(chr(mid))
            
            # Reset the search range for the next character.
            low = 0
            high = 255

    # Join the characters to form the final flag and print it.
    print("".join(decrypted_chars))
    print("Decryption complete.")

if __name__ == "__main__":
    decrypt_flag()

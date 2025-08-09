# This script reconstructs the password based on the validation checks
# from the provided script.

def find_password():
    """
    Builds the correct password by satisfying all the character checks.
    """
    # The original script checks for a length of 52.
    # We'll create a list of that size to hold the characters.
    # Using a placeholder '?' for any characters that might not be defined.
    password = ['?'] * 52

    # The original script checks characters at specific indices.
    # We'll place the required character at each index.
    # Each chr(number) corresponds to a specific character's ASCII value.

    # chr(121) -> 'y'
    password[0] = 'y'
    password[15] = 'y'
    password[27] = 'y'
    password[35] = 'y'
    password[41] = 'y'

    # chr(48) -> '0'
    password[1] = '0'
    password[11] = '0'
    password[19] = '0'
    password[24] = '0'
    password[32] = '0'
    password[44] = '0'
    password[49] = '0'

    # chr(95) -> '_'
    password[2] = '_'
    password[7] = '_'
    password[17] = '_'
    password[20] = '_'
    password[30] = '_'
    password[39] = '_'
    password[47] = '_'

    # chr(100) -> 'd'
    password[3] = 'd'
    password[21] = 'd'
    password[38] = 'd'
    password[50] = 'd'

    # chr(52) -> '4'
    password[4] = '4'

    # chr(119) -> 'w'
    password[5] = 'w'

    # chr(103) -> 'g'
    password[6] = 'g'

    # chr(117) -> 'u'
    password[8] = 'u'

    # chr(110) -> 'n'
    password[9] = 'n'
    password[45] = 'n'

    # chr(99) -> 'c'
    password[10] = 'c'
    password[23] = 'c'
    password[31] = 'c'
    password[48] = 'c'

    # chr(109) -> 'm'
    password[12] = 'm'
    password[25] = 'm'
    password[33] = 'm'

    # chr(112) -> 'p'
    password[13] = 'p'
    password[26] = 'p'
    password[34] = 'p'
    password[40] = 'p'

    # chr(108) -> 'l'
    password[14] = 'l'
    password[28] = 'l'
    password[36] = 'l'

    # chr(51) -> '3'
    password[16] = '3'
    password[29] = '3'
    password[37] = '3'
    password[46] = '3'
    password[51] = '3'

    # chr(116) -> 't'
    password[18] = 't'
    password[42] = 't'

    # chr(101) -> 'e'
    password[22] = 'e'

    # chr(104) -> 'h'
    password[43] = 'h'

    # Join the list of characters into a single string
    return "".join(password)

if __name__ == "__main__":
    correct_password = find_password()
    print(f"The reconstructed password is: {correct_password}")
    print(f"The flag is: flag{{{correct_password}}}")


import numpy as np

def solve_excel_puzzle():
    """
    Solves the cryptographic puzzle defined by the provided Excel worksheet XML.

    The process involves three main steps:
    1. Solving a 27x27 system of linear equations to find intermediate values.
    2. Using the modular inverse of a 3x3 matrix to reverse the core encryption step.
    3. Converting the resulting numerical values back to characters to get the flag.
    """

    # --- Step 1: Solve the System of Linear Equations ---
    # The equations are derived from cells A32:A58 in the worksheet.
    # The 27 variables v[0] to v[26] correspond to the cells E5, F5, G5, E6, ... G13.
    # The mapping is: index = (row - 5) * 3 + (column_index - E_index)

    # Initialize the coefficient matrix (A) and the constant vector (b) for Ax = b
    A = np.zeros((27, 27))
    b = np.zeros(27)

    # Populate A and b based on the equations in the spreadsheet
    # Eq from A32: 8*E5 + 7*F13 - 10*F6 + 6*G11 = 112
    A[0, 0] = 8; A[0, 25] = 7; A[0, 4] = -10; A[0, 20] = 6; b[0] = 112
    # Eq from A33: 5*E10 + 8*E9 + F13 + 3*F6 - 5*G12 = -13
    A[1, 15] = 5; A[1, 12] = 8; A[1, 25] = 1; A[1, 4] = 3; A[1, 23] = -5; b[1] = -13
    # Eq from A34: 10*E9 - 8*F11 + 8*G11 + 9*G7 = 106
    A[2, 12] = 10; A[2, 19] = -8; A[2, 20] = 8; A[2, 8] = 9; b[2] = 106
    # Eq from A35: -E5 - 7*E9 - 8*F11 - 2*F12 + G9 = -127
    A[3, 0] = -1; A[3, 12] = -7; A[3, 19] = -8; A[3, 22] = -2; A[3, 14] = 1; b[3] = -127
    # Eq from A36: -10*E12 + 10*E6 - 7*E9 + 5*F13 + 2*G13 = 280
    A[4, 21] = -10; A[4, 3] = 10; A[4, 12] = -7; A[4, 25] = 5; A[4, 26] = 2; b[4] = 280
    # Eq from A37: -3*E12 - 3*F13 - 8*F5 - 7*F6 - 5*F9 = -376
    A[5, 21] = -3; A[5, 25] = -3; A[5, 1] = -8; A[5, 4] = -7; A[5, 13] = -5; b[5] = -376
    # Eq from A38: -3*E9 + 4*F11 + 9*F6 - 4*F9 + 3*G6 = 40
    A[6, 12] = -3; A[6, 19] = 4; A[6, 4] = 9; A[6, 13] = -4; A[6, 5] = 3; b[6] = 40
    # Eq from A39: 10*F11 - 9*F8 + 2*F9 + G10 - 3*G5 = 0
    A[7, 19] = 10; A[7, 10] = -9; A[7, 13] = 2; A[7, 17] = 1; A[7, 2] = -3; b[7] = 0
    # Eq from A40: -4*E7 - 2*G12 + 3*G13 + 8*G7 + 3*G9 = -34
    A[8, 6] = -4; A[8, 23] = -2; A[8, 26] = 3; A[8, 8] = 8; A[8, 14] = 3; b[8] = -34
    # Eq from A41: -8*E5 + 7*F10 + 8*F12 - 4*F8 - 10*G11 = 347
    A[9, 0] = -8; A[9, 16] = 7; A[9, 22] = 8; A[9, 10] = -4; A[9, 20] = -10; b[9] = 347
    # Eq from A42: 5*E10 + 3*E12 + 8*E5 + 10*F8 + 5*G10 = 245
    A[10, 15] = 5; A[10, 21] = 3; A[10, 0] = 8; A[10, 10] = 10; A[10, 17] = 5; b[10] = 245
    # Eq from A43: 9*E6 - F10 + F12 + 6*F5 + G7 = 406
    A[11, 3] = 9; A[11, 16] = -1; A[11, 22] = 1; A[11, 1] = 6; A[11, 8] = 1; b[11] = 406
    # Eq from A44: -5*E8 - 6*E9 + 6*F11 + 4*F12 = 163
    A[12, 9] = -5; A[12, 12] = -6; A[12, 19] = 6; A[12, 22] = 4; b[12] = 163
    # Eq from A45: -4*F11 - 7*F13 - 4*F5 + 8*G11 = -92
    A[13, 19] = -4; A[13, 25] = -7; A[13, 1] = -4; A[13, 20] = 8; b[13] = -92
    # Eq from A46: 6*E10 - 4*E9 - F10 - 3*G9 = 23
    A[14, 15] = 6; A[14, 12] = -4; A[14, 16] = -1; A[14, 14] = -3; b[14] = 23
    # Eq from A47: 6*E11 - 5*E5 + 8*F12 - 9*G8 - 2*G9 = 212
    A[15, 18] = 6; A[15, 0] = -5; A[15, 22] = 8; A[15, 11] = -9; A[15, 14] = -2; b[15] = 212
    # Eq from A48: 5*E11 - 2*E12 - 10*E13 + 8*F13 + 6*G13 = 317
    A[16, 18] = 5; A[16, 21] = -2; A[16, 24] = -10; A[16, 25] = 8; A[16, 26] = 6; b[16] = 317
    # Eq from A49: -8*E10 - 7*E7 - 2*E9 + 4*F13 - 3*G8 = -350
    A[17, 15] = -8; A[17, 6] = -7; A[17, 12] = -2; A[17, 25] = 4; A[17, 11] = -3; b[17] = -350
    # Eq from A50: -10*F11 - 3*F12 + 6*F6 + G12 + 8*G8 = 91
    A[18, 19] = -10; A[18, 22] = -3; A[18, 4] = 6; A[18, 23] = 1; A[18, 11] = 8; b[18] = 91
    # Eq from A51: 9*E5 - 3*F11 + 7*F7 + 10*F8 - 7*G6 = -99
    A[19, 0] = 9; A[19, 19] = -3; A[19, 7] = 7; A[19, 10] = 10; A[19, 5] = -7; b[19] = -99
    # Eq from A52: -6*E11 + 9*E8 + 6*F13 - 4*F5 - 9*G5 = -385
    A[20, 18] = -6; A[20, 9] = 9; A[20, 25] = 6; A[20, 1] = -4; A[20, 2] = -9; b[20] = -385
    # Eq from A53: -7*E10 + 4*E6 - 5*F13 + 10*F5 - 7*G13 = 7
    A[21, 15] = -7; A[21, 3] = 4; A[21, 25] = -5; A[21, 1] = 10; A[21, 26] = -7; b[21] = 7
    # Eq from A54: 5*E12 - 6*E7 + 8*F7 + 8*G13 - 7*G5 = -115
    A[22, 21] = 5; A[22, 6] = -6; A[22, 7] = 8; A[22, 26] = 8; A[22, 2] = -7; b[22] = -115
    # Eq from A55: -6*E12 + 5*E7 - 10*F10 + 6*F11 + F6 = -190
    A[23, 21] = -6; A[23, 6] = 5; A[23, 16] = -10; A[23, 19] = 6; A[23, 4] = 1; b[23] = -190
    # Eq from A56: 8*E6 + 3*F11 - 7*F9 + 8*G10 + 2*G8 = 233
    A[24, 3] = 8; A[24, 19] = 3; A[24, 13] = -7; A[24, 17] = 8; A[24, 11] = 2; b[24] = 233
    # Eq from A57: -9*F10 - 2*F11 + 8*F6 + 5*F8 - 4*G5 = -322
    A[25, 16] = -9; A[25, 19] = -2; A[25, 4] = 8; A[25, 10] = 5; A[25, 2] = -4; b[25] = -322
    # Eq from A58: 2*E10 - 7*E11 - 5*E13 - 5*E9 - G12 = -245
    A[26, 15] = 2; A[26, 18] = -7; A[26, 24] = -5; A[26, 12] = -5; A[26, 23] = -1; b[26] = -245

    # Solve the system Ax = v_intermediate
    v_intermediate = np.linalg.solve(A, b)
    # Round to nearest integer to handle potential floating point inaccuracies
    v_intermediate = np.round(v_intermediate).astype(int)

    # --- Step 2: Reverse the Matrix Multiplication ---
    # The encryption uses `Result = M * Input mod 37`. We need `Input = M_inv * Result mod 37`.
    # The inverse of the matrix M (from cells C5:C13) modulo 37 has been pre-calculated.
    M_inv = np.array([
        [32, 21, 27],
        [11, 23, 10],
        [23, 25, 33]
    ])

    # Reshape the intermediate results into 9 blocks of 3 (for each 3-char chunk of the original flag)
    result_blocks = v_intermediate.reshape(9, 3)
    
    original_numerical_values = []
    for block in result_blocks:
        # Apply the inverse matrix to each block
        input_block = np.dot(M_inv, block) % 37
        original_numerical_values.extend(input_block)

    # --- Step 3: Convert Numbers to Characters ---
    # This reverses the mapping defined in row 3 of the spreadsheet.
    # 0-9 -> '0'-'9', 10 -> '_', 11-36 -> 'a'-'z'
    flag = ""
    for val in original_numerical_values:
        if 0 <= val <= 9:
            flag += chr(val + 48)  # ASCII for '0' is 48
        elif val == 10:
            flag += '_'
        elif 11 <= val <= 36:
            flag += chr(val + 86)  # ASCII for 'a' is 97 (11+86=97)
        else:
            flag += '?' # Should not happen

    return flag

if __name__ == '__main__':
    solution = solve_excel_puzzle()
    print("--- Excel Puzzle Solver ---")
    print(f"\nThe calculated solution is:\n{solution}")


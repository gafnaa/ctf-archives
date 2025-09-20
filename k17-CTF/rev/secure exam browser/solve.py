# solve.py

def solve_seb():
    """
    Solves the Secure Exam Browser challenge by reversing the password
    validation algorithm.
    """
    # The 88-byte encrypted data array found in the binary 
    v1_signed = [
        19, 17, 25, -63, 10, 36, 39, -7,
        93, -71, 42, 73, 73, 16, 51, -47,
        122, 17, 9, -63, 125, 36, 30, -7,
        119, -71, 20, 73, 81, 16, 28, -47,
        95, 17, 2, -63, 21, 36, 97, -7,
        71, -71, 43, 73, 64, 16, 42, -47,
        118, 17, 3, -63, 70, 36, 47, -7,
        96, -71, 19, 73, 77, 16, 13, -47,
        66, 17, 4, -63, 118, 36, 24, -7,
        124, -71, 39, 73, 120, 16, 127, -47,
        105, 17, 21, -63, 26, 36, 98, -7
    ]

    # Convert signed bytes to unsigned (0-255) for consistent arithmetic
    v1_unsigned = [b & 0xFF for b in v1_signed]
    
    # Split the data into 11 chunks of 8 bytes each
    chunks = [v1_unsigned[i:i+8] for i in range(0, 88, 8)]

    password = []
    
    for chunk in chunks:
        val = 0
        
        # Reverse Step 8: val = (val + d7) & 0xFF
        val = (val + chunk[7]) & 0xFF
        # Reverse Step 7: val = val ^ d6
        val = val ^ chunk[6]
        # Reverse Step 6: val = (val + d5) & 0xFF
        val = (val + chunk[5]) & 0xFF
        # Reverse Step 5: val = val ^ d4
        val = val ^ chunk[4]
        # Reverse Step 4: val = (val + d3) & 0xFF
        val = val ^ chunk[3]
        # Reverse Step 3: val = val ^ d2
        val = val ^ chunk[2]
        # Reverse Step 2: val = (val - d1) & 0xFF
        val = (val - chunk[1]) & 0xFF
        # Reverse Step 1: val = val ^ d0
        char_code = val ^ chunk[0]
        
        password.append(chr(char_code))

    return "".join(password)

if __name__ == "__main__":
    correct_password = solve_seb()
    print(f"✅ Correct password found: {correct_password}")
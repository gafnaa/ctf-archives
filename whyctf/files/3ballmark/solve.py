# A Python script to replicate the create_flag(10) function.

def decrypt_flag():
    """
    This function reconstructs the flag by simulating the logic of the
    create_flag function from the provided C code.
    """
    # Source strings as defined in the C code's data section
    msg_start_0 = "This is 3 ball Mark and his magic bag! He h45 one yellow and two blue balls! Can you find the yellow ball ten times in a row?"
    msg_shuffle = "Shufflin9 my balls..."
    msg_take_a_pick_0 = "Take a pick {1/2/3}: "
    msg_wrong_pick = "T00 bad you picked the wrong 84LL!"
    msg_correct_pick = "You picked 7he correct 6all "

    # The value passed to create_flag from the main function is 10
    a1 = 10

    # An empty list to store the characters of the flag
    flag_chars = []

    # Replicate each strncat operation from the C code
    flag_chars.append(msg_shuffle[a1 - 7])
    flag_chars.append(msg_start_0[a1 + 2])
    flag_chars.append(msg_start_0[a1 + 1])
    flag_chars.append(msg_wrong_pick[a1 + 17])
    flag_chars.append(msg_take_a_pick_0[a1 + 2])
    flag_chars.append(msg_correct_pick[a1 + 1])
    flag_chars.append(msg_start_0[a1 + 33])
    flag_chars.append(msg_take_a_pick_0[a1 + 5])
    flag_chars.append(msg_wrong_pick[a1 + 19])
    flag_chars.append(msg_start_0[a1 + 34])
    flag_chars.append(msg_correct_pick[a1 + 13])
    flag_chars.append(msg_start_0[10 * a1 + 2])
    flag_chars.append(msg_shuffle[a1 - 2])
    flag_chars.append(msg_start_0[10 * a1 + 2])
    flag_chars.append(msg_shuffle[a1 // 2 - 1])
    flag_chars.append(msg_correct_pick[a1 + 13])
    flag_chars.append(msg_take_a_pick_0[a1 + 5])
    flag_chars.append(msg_correct_pick[a1 + 13])
    flag_chars.append(msg_start_0[a1 + 33])
    flag_chars.append(msg_take_a_pick_0[a1 - 1])
    flag_chars.append(msg_take_a_pick_0[a1 + 7])
    flag_chars.append(msg_correct_pick[a1 + 3])
    flag_chars.append(msg_correct_pick[a1 + 3])
    flag_chars.append(msg_wrong_pick[a1 // 2 + 1])
    flag_chars.append(msg_wrong_pick[a1 + 19])
    flag_chars.append(msg_wrong_pick[a1 + 19])
    flag_chars.append(msg_start_0[a1 + 34])
    flag_chars.append(msg_wrong_pick[a1 + 19])
    flag_chars.append(msg_correct_pick[a1 + 1])
    flag_chars.append(msg_shuffle[a1 // 2 - 1])
    flag_chars.append(msg_wrong_pick[a1 - 9])
    flag_chars.append(msg_shuffle[a1 - 2])
    flag_chars.append(msg_correct_pick[a1 + 3])
    flag_chars.append(msg_wrong_pick[a1 // 2 + 1])
    flag_chars.append(msg_wrong_pick[a1 - 9])
    flag_chars.append(msg_take_a_pick_0[a1 + 7])
    flag_chars.append(msg_start_0[a1])
    flag_chars.append(msg_take_a_pick_0[a1 + 8])

    # Join the characters to form the final flag string
    return "".join(flag_chars)

# --- Execution ---
if __name__ == "__main__":
    decrypted_flag = decrypt_flag()
    print("✅ Decryption successful!")
    print(f"The reward is: {decrypted_flag}")
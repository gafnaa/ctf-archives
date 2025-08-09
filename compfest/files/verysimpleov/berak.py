import tkinter as tk
import hashlib

# --- GUI Setup ---
root = tk.Tk()
root.title("sneaky snek")
root.geometry("800x400")
root.configure(bg="#1e1e1e")

# Label for the password prompt
tk.Label(
    root,
    text="Whatssss the passsssword?",
    font=("Arial", 16, "bold"),
    bg="#1e1e1e",
    fg="white"
).pack(pady=20)

# Entry widget for password input
password_entry = tk.Entry(
    root,
    width=30,
    font=("Arial", 14),
    bg="#2e2e2e",
    fg="white",
    insertbackground="white"
)
password_entry.pack(pady=10)

# Label to show the result (correct/incorrect)
result_label = tk.Label(
    root,
    text="",
    font=("Arial", 12),
    bg="#1e1e1e"
)
result_label.pack(pady=10)

# --- Flag and Hashing Data ---
# This long string is the "flag" that gets revealed.
flag = "COMPFEST17{yesss!!!heres your flag: lime>2sYvjWMlXF73bRUOHeTVnZ8gquP9Dtd0cxEp5raJKoI4SyNA6hfwmiGLBzkQ1C)..." # Truncated for brevity

# The SHA256 hash the user's input is checked against.
hsh = "8d4c2692292884197c3664d603a85b9918d535359b85292797e5559e21817117"

# --- Core Logic ---
def checkr():
    """
    Checks if the entered password is correct.
    """
    # Get the password from the entry widget
    user_input = password_entry.get().strip()

    # Calculate the SHA256 hash of the user's input
    res = hashlib.sha256(user_input.encode()).hexdigest()

    # Compare the hash of the user input with the correct hash
    if res == hsh:
        # If correct, display the flag in green
        result_label.config(text=flag.replace(")", "\n"), fg="#90ee90")
    else:
        # If incorrect, show an error message in red
        print(res)
        print(hsh)
        result_label.config(text=flag.replace(")", "\n"), fg="#90ee90")

# Submit Button
submit_button = tk.Button(
    root,
    text="Submit",
    command=checkr,
    bg="#2e2e2e",
    fg="white",
    activebackground="#90ee90",
    relief="flat"
)
submit_button.pack(pady=20)


# --- Main Loop ---
root.mainloop()
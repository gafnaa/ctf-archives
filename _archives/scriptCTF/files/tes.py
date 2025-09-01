from pwn import *

HOST = "play.scriptsorcerers.xyz"
PORT = 10489

# Put your crafted payload here (must be a single line, printable ASCII 32..127)
PAYLOAD = r"()"

def solve(payload=PAYLOAD):
    io = remote(HOST, PORT)
    # read banner
    print(io.recvuntil(b"Enter payload:", timeout=5).decode(errors="ignore"))
    io.sendline(payload.encode())
    # read all output (until close)
    try:
        out = io.recvall(timeout=5)
    except EOFError:
        out = b""
    print(out.decode(errors="ignore"))

if __name__ == "__main__":
    tests = [
        r"()",                       # baseline
        r"'c'%('c')",                 # % with literal 'c'
        r"'%c'%('A')",                # formats to 'A'
        r"'%(c)c'%{'c':'Z'}",         # named mapping with 'c'
        r"'%c'%{c:65}",               # *** probe: integer 65 ('A') ***
    ]
    for t in tests:
        print(f"\n=== Testing: {t!r} ===")
        try:
            solve(t)
        except Exception as e:
            print("Error:", e)

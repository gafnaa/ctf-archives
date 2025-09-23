import sys
import signal
from typing import Optional

from Crypto.Util.number import isPrime, getRandomRange


class LCG:
    
    def __init__(self, mod: int, seed: int):
        self.mod = mod - 1
        self.A = getRandomRange(1, mod)
        self.B = getRandomRange(1, mod)
        self.state = seed
    def next(self) -> int:
        self.state = (self.A * self.state + self.B) % self.mod
        return self.state >> 256

class Challenge:
    def __init__(self):
        self.lcg = None

        # group params (set after user supplies p)
        self.p: Optional[int] = None
        self.g: Optional[int] = None

        # secret ElGamal key (over Z_p*)
        self.x: Optional[int] = None   # private
        self.h: Optional[int] = None   # g^x mod p (kept secret)

        # whether p/g/x/h are initialized
        self.ready: bool = False

        # Cap oracle calls (optional safety); set None for unlimited
        self.enc_limit: Optional[int] = None
        self.enc_count: int = 0
        self.s = getRandomRange(1, 2**512)
        self.c = getRandomRange(1, 2**128)

    # ---- parameter setup ----
    def set_p(self, p: int) -> str:
        if self.ready:
            return "p already set. Restart the process to choose a new modulus.\n"
        if p <= 3 or p.bit_length() != 512 or not isPrime(p):
            return "Invalid p: must be a 512-bit prime.\n"

        self.p = p
        while True:
            g = getRandomRange(2, p - 1)
            if pow(g, (p - 1) // 2, p) != 1:
                self.g = g
                break

        # Secret ElGamal key
        self.x = getRandomRange(2, p - 2)
        self.h = pow(self.g, self.x, self.p)  # kept secret
        self.lcg = LCG(p, self.s)

        self.ready = True
        return "OK: modulus set and parameters initialized.\n"

    def show_params(self) -> str:
        if not self.ready:
            return "Set p first with: setp (int)\n"
        out = []
        out.append(f"p            = 0x{self.p:x}")
        out.append(f"g            = 0xREDACTED")
        out.append(f"lcg.a        = 0x{self.lcg.A:x}")
        out.append(f"lcg.b        = 0x{self.lcg.B:x}")
        return "\n".join(out) + "\n"

    def enc(self, m: int) -> str:
        if not self.ready:
            return "Set p first with: setp (int)\n"
        if not (1 <= m < self.p):
            return "Message m must satisfy 1 <= m < p.\n"

        if self.enc_limit is not None and self.enc_count >= self.enc_limit:
            return "Encryption limit reached.\n"

        k = self.lcg.next()
        r = k ^ self.c

        c1 = pow(self.g, r, self.p)
        s  = pow(self.h, r, self.p)
        c2 = (m * s) % self.p

        self.enc_count += 1
        return f"c1 = 0x{c1:x}\nc2 = 0x{c2:x}\n"

    # ---- Guess the seed ----
    def try_guess(self, val: int, c: int) -> str:
        if val == self.s and c == self.c:
            return read_flag().decode("utf-8", errors="replace") + "\n"
        return "Nope.\n"

# ---------------------------
# I/O helpers
# ---------------------------

HELP_TEXT = """\
Commands:
  setp <int>     : set 512-bit prime modulus p (decimal or 0x... hex)
  params         : show public parameters
  enc <m>        : encrypt your integer m (1 <= m < p) -> prints c1, c2 (hex)
  guess <s> <c>  : guess the secrets
  help           : show this help
  exit           : quit
"""

def parse_int(s: str) -> Optional[int]:
    s = s.strip()
    try:
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s, 10)
    except ValueError:
        return None

def read_flag() -> bytes:
    try:
        with open("flag.txt", "rb") as f:
            return f.read().strip()
    except FileNotFoundError:
        return b"CTF{flag_file_missing}"

# ---------------------------
# Main REPL
# ---------------------------

def main():
    chal = Challenge()
    signal.alarm(120)
    print("=== Modular ElGamal Oracle (LCG-seeded) ===")
    print("Your goal: recover the initial LCG seed s.")
    print(HELP_TEXT)
    sys.stdout.flush()

    for _ in range(50):
        line = input("$ ").strip()
        parts = line.split()
        cmd = parts[0].lower()

        if cmd == "exit" or cmd == "quit":
            print("bye")
            return

        if cmd == "help":
            print(HELP_TEXT, end="")
            continue

        if cmd == "setp":
            if len(parts) != 2:
                print("usage: setp <int>")
            else:
                val = parse_int(parts[1])
                if val is None:
                    print("invalid integer for p")
                else:
                    sys.stdout.write(chal.set_p(val))
            continue

        if cmd == "params":
            sys.stdout.write(chal.show_params())
            continue

        if cmd == "enc":
            if len(parts) != 2:
                print("usage: enc <m>")
                continue
            m = parse_int(parts[1])
            if m is None:
                print("invalid integer for m")
                continue
            sys.stdout.write(chal.enc(m))
            continue

        if cmd == "guess":
            if len(parts) != 3:
                print("usage: guess <s> <m>")
                continue
            s = parse_int(parts[1])
            c = parse_int(parts[2])
            sys.stdout.write(chal.try_guess(s, c))
            continue
        
        if cmd == "admin":
            print(f"G={chal.g}")

        print("unknown command; type 'help'")

if __name__ == "__main__":
    main()

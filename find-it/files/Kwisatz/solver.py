from pwn import *
import random
from math import gcd
from precomputed_pairs import precomputed  # This file must exist

context.log_level = 'info'

# Server details
host = 'ctf.find-it.id'
port = 6101

# Challenge modulus
n = 10205316970729431639485797664559886873490701487420041461102004580735751585751742938892976099986403177553363193830393487376567969420541261258134979327616363126253347148610544049807204226284930907503420405166209168541128632688637445870726287383056390377377382107622861504746212131179321468457103686904634978985262225083923899729078173292553918759616384301941301278845655112236714906572052945789912210749004588396399367890793347769585000314877970596365280369362958611301633074434160115833714459835933860197771690614293763100020927442209269135680658111369923029908840001532934157556701107140402652365541506235916261071723

def solve_round(io, x):
    verifier_rounds = 256
    used_s = set()
    used_z = set()

    for _ in range(verifier_rounds):
        # Generate a unique, coprime s
        while True:
            s = random.randint(2, n - 1)
            if gcd(s, n) == 1 and s not in used_s:
                break
        used_s.add(s)

        io.sendlineafter("Give me an s:", str(s))
        io.recvuntil("determine your fate:\n")
        b = int(io.recvline().strip())
        b_mod = b % 2

        io.sendlineafter("Your choice [1/2/3]:", "1")

        z = s if b_mod == 0 else (s * x) % n

        if z in used_z:
            print("Repeated z — fail")
            return False
        used_z.add(z)

        io.sendlineafter("Give me a z:", str(z))
        line = io.recvline().decode()
        if "Good" in line:
            print("[+] Correct response")
        else:
            print("[-] Failed this round")
            return False
    return True

def main():
    passed = 0

    while passed < 100:
        io = remote(host, port)

        io.recvuntil("n = ")
        io.recvline()  # skip n line, we already know n

        io.recvuntil("y = ")
        y = int(io.recvline().strip())
        print(f"[*] y = {y}")

        if y not in precomputed:
            print("[-] y not in precomputed list, skipping")
            io.sendlineafter("Your choice [1/2]:", "2")
            io.close()
            continue

        x = precomputed[y]

        io.sendlineafter("Your choice [1/2]:", "1")

        if solve_round(io, x):
            passed += 1
            print(f"[+] Passed {passed}/100")
        else:
            print("[-] Failed. Resetting counter.")
            passed = 0

        io.close()

    print("[!] Completed 100 passes! Flag should be shown.")

if __name__ == "__main__":
    main()

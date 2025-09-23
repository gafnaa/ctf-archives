from Crypto.Util.number import isPrime, long_to_bytes
import gmpy2 

n = 18307564183336174372957570419285112053386287578636115613810768749885553622091399241390778725602944089106231437595887
e = 65537
c = 14461562873315648876900863314412430050179928115118140218391238322269424888840823494182924552959513459002994495040816
r = 272617646727976431124665621907966000454

def nextPrime(num):
    num += 1
    while not isPrime(num):
        num += 1
    return num

r_p = nextPrime(r)
print(f"Found nextPrime(r): {r_p}\n")
q_approx = gmpy2.isqrt(n // (r_p + r))
print(f"Approximated q: {q_approx}\n")
q_candidate = int(q_approx)
q = 0
p = 0

for _ in range(5000):
    if n % q_candidate == 0:
        q = q_candidate
        p = n // q
        if isPrime(p) and isPrime(q):
            print(f"Found q: {q}")
            print(f"Found p: {p}\n")
            break
    q_candidate -= 1

if p == 0 or q == 0:
    print("Failed to find factors. Exiting.")
    exit()

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)

print(flag.decode())
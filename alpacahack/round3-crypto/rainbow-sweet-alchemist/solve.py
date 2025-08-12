import random
from math import prod, gcd
from Crypto.Util.number import isPrime, long_to_bytes, inverse

# Provided values from the challenge output
n = 2350478429681099659482802009772446082018100644248516135321613920512468478639125995627622723613436514363575959981129347545346377683616601997652559989194209421585293503204692287227768734043407645110784759572198774750930099526115866644410725881688186477790001107094553659510391748347376557636648685171853839010603373478663706118665850493342775539671166315233110564897483927720435690486237018231160348429442602322737086330061842505643074752650924036094256703773247700173034557490511259257339056944624783261440335003074769966389878838392473674878449536592166047002406250295311924149998650337286245273761909
e = 65537
c = 9454556863749006119825129838551804180930867996527687438644458878916738335361947844364799860182268080218694597626520604954959395141860999596191505945808069288545026084870906149142265277104325923621854660149100829467477203459439634595844308041688017878317218827434157355730978467269695663698572747202109991420040379146467737887505113109489533482632882818769189255754022429493154395339829800059496804517809316084796411616705054470030362764964092901853858632659085164530446730789998000497412772426465138742141279302235558029258772175141248590241406152365769987248447302410223052788101550323890531305166459

# --- Pollard's p-1 Variant Logic ---

# 1. Regenerate the sequence of deterministic primes
r = random.Random(0)
def deterministicGetPrime():
    while True:
        if isPrime(p := r.getrandbits(64)):
            return p

print("⚙️  Generating the deterministic sequence of 64-bit primes...")
_ = deterministicGetPrime() # Consume the first prime used in the server's assert

# Generate a larger pool of probable factors. 400 should be more than enough.
# This is the only line that has been changed.
num_primes_to_generate = 400
factors = [deterministicGetPrime() for _ in range(num_primes_to_generate)]
print(f"✅ Generated {num_primes_to_generate} candidate primes.")

# 2. Calculate the exponent E for the attack
print("⚙️  Calculating massive exponent for the attack...")
E = prod(factors)
print("✅ Exponent calculated.")

# 3. Perform the GCD attack
print("⚙️  Executing Pollard's p-1 variant: gcd(a^E - 1, n)...")
a = 2
a_to_the_E = pow(a, E, n)
p_found = gcd(a_to_the_E - 1, n)

# 4. Check results and decrypt
if 1 < p_found < n:
    print("✅ Success! A factor has been found.")
    q_found = n // p_found

    if isPrime(p_found) and isPrime(q_found) and p_found * q_found == n:
        print("✅ Factors p and q confirmed.")
        phi = (p_found - 1) * (q_found - 1)
        d = inverse(e, phi)
        m = pow(c, d, n)
        flag = long_to_bytes(m)
        c_bytes = long_to_bytes(c)
        keystream = long_to_bytes(m)
        final_flag = bytes([keystream[i] ^ c_bytes[i] for i in range(len(c_bytes))])
        print("\n🎉 Decryption Complete! 🎉")
        print(f"🚩 Final Flag: {final_flag.decode()}")
    else:
        print("❌ Error: Something went wrong with the factorization.")

elif p_found == n:
    print("❌ Attack failed: gcd(a^E - 1, n) = n.")
    print("   This means the factors of (p-1) and (q-1) were both captured.")
    print("   Try reducing `num_primes_to_generate`.")
else: # p_found == 1
    print("❌ Attack failed: gcd(a^E - 1, n) = 1.")
    print("   This means the factors for p-1 and q-1 were not in the generated set.")
    print("   Try increasing `num_primes_to_generate`.")
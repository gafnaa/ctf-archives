from Crypto.Util.number import long_to_bytes

a = 14471576219266074581
share = 16953595432002429419
evaluated = 46630100669869476338251632206325916950142668894613493451490488193371312584383513476451377416970367368029480641136391419764107625315006704521529547206120271699384851112062955396601583394244936907502839571606528866198546718256976953732294699054809760163546910083018075805198802737977303017215543219067958532569739070270358835020828437248167220513250693844936274555359578985064756327247880692451586148579772

# The polynomial is s + a*share^2*(sum of terms)
# So s = evaluated mod a*share^2 if s < a*share^2

share_sq = share * share
a_share_sq = a * share_sq

# Try different modulo sizes since initial approach gave binary output
for k in range(1, 10):
    modulus = a_share_sq // k
    s = evaluated % modulus
    flag = long_to_bytes(s)
    try:
        if b'flag{' in flag:
            print(f"Found flag with modulus divisor {k}: {flag}")
            break
    except:
        continue

# If that doesn't work, try looking for the flag pattern in the raw bytes
s = evaluated % a_share_sq
flag_bytes = long_to_bytes(s)
print("Raw bytes:", flag_bytes)

# Sometimes the flag is in the beginning or end
for i in range(0, len(flag_bytes)-5):
    if flag_bytes[i:i+5] == b'flag{':
        print("Found flag in bytes:", flag_bytes[i:])
        break
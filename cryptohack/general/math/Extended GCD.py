def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x, y = extended_gcd(b, a % b)
        return (g, y, x - (a // b) * y)

p = 26513
q = 32321

gcd_val, u, v = extended_gcd(p, q)
print(f"gcd: {gcd_val}, u: {u}, v: {v}")
print("Lower of u and v is:", min(u, v))

from hashlib import sha512

def xor(a, b):
  """Performs XOR operation on two byte strings."""
  return bytes([x ^ y for x, y in zip(a, b)])

def iroot(n, x):
  """
  Computes the integer n-th root of x using a binary search.
  """
  if x < 0: return 0, False
  if x == 0: return 0, True
      
  low = 1
  high = x
  
  while low <= high:
      mid = (low + high) // 2
      if mid == 0: return 0, False
      
      mid_pow = mid ** n
      
      if mid_pow == x:
          return mid, True
      elif mid_pow < x:
          low = mid + 1
      else:
          high = mid - 1
  
  if high ** n == x:
      return high, True
  else:
      return high, False

# 1. Parse the given values
p_hex = "1cec7c3ff93ca538e71f334e83d905eabd894729a1b515b89dc2392036bc7e5d59fad2c35dbb0a8903c8bb2e9cd5e4779a92d3f361eb1ce9fa2530c47881a8719763f828360138373ffa2ce627f8ccad08e9b5ead178c614f7899adc6a14fa33aa2216c463a04041e78cffa2c68963c6ff422a076bedd32236282eb3bd1b7ba870a3b1c8f639cd536cba329b10a6cf7b4ef78bd11052ff8a0d432fb6d3b221742aa1da6914876e94aca5abdaeef30acdfc90cbc621245ad288a634e8bdf4152ea8ed0062c872ace7b4011dc5743fa9c424413f4e3e8fa5c5513fd4a711141f2ef68c01177f78945db623ac6cc762a6813f11cc278a143ea657bf309e281ef59048a29f279c9ad8b37f221ac06242f577bba985a2aaec051d95391a9681f905472f4e7d1322da492639ee4a5ac776a476cece55f9dfb782c1ef869deed2226691d3157fbb6b131968ebfb1fe5bc1e44a158f1e2321c001355cc9cb3344f6b09b78d965a807cd60d58a9efbab8c6d4f75c8e5ac7c9cf0e5409b55bb2133129272685913be02166c6bffe3747ccd186b6c26fc9f09"
ct_hex = "43edcf6275293ce97d716f49875c4bdba37f6ab30f15a53f09b72bf3816edf6b92618fb56d569d911b2f6fe7a36d4a854022dddf671dc89b4800bc1605822aab72d3"

p = int(p_hex, 16)
ct = bytes.fromhex(ct_hex)

a_found, b_found = None, None

# --- Main logic ---
print("Previous hypotheses failed. Testing the final hypothesis...")
print("Hypothesis: b = 51")

b_hypo = 51
# Calculate a^51 = p - 51^52
candidate_a_pow_51 = p - (b_hypo ** 52)

if candidate_a_pow_51 > 0:
    a, is_perfect_a = iroot(51, candidate_a_pow_51)
    
    if is_perfect_a:
        a_found, b_found = a, b_hypo
else:
    print("❌ Condition for b=51 failed because p - 51^52 is not positive.")

# 4. Decrypt the flag if a solution was found
if a_found is not None and b_found is not None:
    print(f"\n✅ Success! Found solution:\n a = {a_found}\n b = {b_found}\n")
    
    key_str = str(a_found) + str(b_found)
    key_hash = sha512(key_str.encode()).digest()
    
    flag_bytes = xor(ct, key_hash)
    flag = flag_bytes.decode()
    
    print(f"🚩 Recovered Flag:\n{flag}")
else:
    print("\n❌ Failed to find a solution. The mystery continues...")
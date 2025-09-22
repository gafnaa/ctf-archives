encrypted_flag = "yptnk\"C(a(n(a(t(a)u+p+v)v*v'v't,v-r*"
key = 0x2a

decrypted_flag = ""
for char in encrypted_flag:
  decrypted_flag += chr(ord(char) ^ key)

print(decrypted_flag)

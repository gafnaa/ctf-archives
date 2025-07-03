from Crypto.Util.number import *


data = "11515195063862318899931685488813747395775516287289682636499965282714637259206269"

flag = long_to_bytes(int(data)).decode('utf-8')
print(flag)
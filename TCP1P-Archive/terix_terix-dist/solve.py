data = [
    [82, 65, 77, 65], 
    [68, 65, 78, 123], 
    [69, 52, 115, 121], 
    [45, 99, 104, 52], 
    [108, 108, 95, 77], 
    [52, 116, 114, 49], 
    [120, 33, 125, 33]
]

flag = ""
for row in data:
  for number in row:
    flag += chr(number)

print(flag)
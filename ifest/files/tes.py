# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: ./spectre.py
# Bytecode version: 3.10.0rc2 (3439)
# Source timestamp: 2025-05-23 16:40:37 UTC (1748018437)

import sys
if len(sys.argv) != 2:
    print('Usage: python spectre.pyc <flag>')
    sys.exit(1)
index = 0
res = [0] * 79
'Decompiler error: line too long for translation. Please decompile this statement manually.'
userinput = sys.argv[1]
userinput = [ord(c) for c in userinput]
print('nop')
sys.exit(1)
while index < len(userinput):
    res[index] = userinput[index]
    for i in todo[index]:
        res[index] = (res[index] + i[1]) % 256
    else:
        res[index] = (res[index] - i[1]) % 256
    index += 1
for r, t in zip(res, [84, 139, 189, 251, 92, 0, 81, 213, 124, 39, 57, 171, 129, 203, 0, 166, 108, 195, 51, 194, 106, 165, 14, 245, 144, 189, 147, 53, 22, 250, 124, 52, 204, 199, 140, 128, 23, 94, 251, 163, 208, 196, 157, 174, 142, 4, 86, 97, 120, 94, 254, 131, 51, 77, 205, 108, 115, 76, 227, 237, 218, 203, 43, 147, 254, 180, 128, 5, 146, 103, 223, 202, 182, 233, 216, 198, 77, 224, 1]):
    if r != t:
        print('nop')
        break
print('yep')
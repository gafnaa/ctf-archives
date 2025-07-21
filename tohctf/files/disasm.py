# solver.py
pairs = [
    (137, 253), (200, 167), (204, 164), (128, 251), (223, 176),
    (235, 131), (102, 57), (155, 241), (199, 244), (14, 61),
    (68, 62), (238, 177), (16, 127), (137, 225), (52, 107),
    (170, 199), (144, 164), (76, 34), (103, 56), (155, 170),
    (30, 65), (13, 105), (62, 14), (120, 22), (169, 221),
    (55, 104), (180, 223)
]

# Dekode dengan XOR
flag_bytes = [a ^ b for a, b in pairs]
flag = ''.join(map(chr, flag_bytes))

# Finalisasi (opsional perbaikan manual jika perlu)
print("Recovered Flag:", flag)

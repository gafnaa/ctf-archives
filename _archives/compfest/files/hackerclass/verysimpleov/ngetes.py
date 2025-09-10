import marshal, dis

with open("out.pyc", "rb") as f:
    f.read(16)  # Lewati header
    code = marshal.load(f)

# Tampilkan struktur kode
print(dis.code_info(code))
dis.dis(code)
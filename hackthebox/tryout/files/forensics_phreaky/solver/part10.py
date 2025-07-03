import base64

encoded_data = """
UEsDBAoACQAAAGZ3Zlj/Gb5u6QAAAN0AAAAXABwAcGhyZWFrc19wbGFuLnBkZi5wYXJ0MTBVVAkA
A8CE6GXAhOhldXgLAAEE6AMAAAToAwAA22IkVozT4hpv67dNaBas9lborysg+A87Nq9ckagEYzZf
6R881phUvE8tVImHS4p8pdcmlfnz+icS0+CeENKNQFhJMlHl6jxDyKI4LbzJ2+YWZ/zxaQ2/AMR6
GykbDScNlnGtlXOcXe+RDYCrgLgB1iAMLvziMF27db2C9opPLx/x8l+FiQ0Gogn6H4RKjbh9SDOk
qzGENuXmo46TlISrjIFBMPvsYpcKHDknDxgHPZvejQj4DZOe//3Qyvksr5xsNIQCx/ezXJVZKqDk
Um2D9GsQjGcN8kmCQbxpbYq64iOkYj/fgcptZWZQSwcI/xm+bukAAADdAAAAUEsBAh4DCgAJAAAA
ZndmWP8Zvm7pAAAA3QAAABcAGAAAAAAAAAAAALSBAAAAAHBocmVha3NfcGxhbi5wZGYucGFydDEw
VVQFAAPAhOhldXgLAAEE6AMAAAToAwAAUEsFBgAAAAABAAEAXQAAAEoBAAAAAA==
"""

decoded_bytes = base64.b64decode(encoded_data)

with open("part10.zip", "wb") as f:
    f.write(decoded_bytes)

print("File ZIP berhasil diekstrak: part10.zip")


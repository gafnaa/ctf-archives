import base64

encoded_data = """
UEsDBBQACQAIAGZ3Zlg68XpvyAAAAN0AAAAXABwAcGhyZWFrc19wbGFuLnBkZi5wYXJ0MTFVVAkA
A8CE6GXAhOhldXgLAAEE6AMAAAToAwAA1XFxuJqaVlE3BajxvkjKFU1UNArCCd046Zq3hSv3YQq3
5vkNnyX2RgCWLO8+IMONpTPAeu8lrkrLU0dyNmk4qZayus+5yfEi8/YCmAgf0PqAoUZq81/8MJ3q
/zvIPUIKqy+P7V6EUEy3EXIvexGB9r5vI5Vuyx/y00ct3/ooluaHjBRmmHxxotAm9vl+kJWqmJou
9fKDg/RVQX5GUNUZ1XNeBD3HBzZqjZOVkDS1iWI8FCUBtE8reYicAN8vN1+4n9zHYa0FM/lQSwcI
OvF6b8gAAADdAAAAUEsBAh4DFAAJAAgAZndmWDrxem/IAAAA3QAAABcAGAAAAAAAAAAAALSBAAAA
AHBocmVha3NfcGxhbi5wZGYucGFydDExVVQFAAPAhOhldXgLAAEE6AMAAAToAwAAUEsFBgAAAAAB
AAEAXQAAACkBAAAAAA==
"""

decoded_bytes = base64.b64decode(encoded_data)

with open("part11.zip", "wb") as f:
    f.write(decoded_bytes)

print("File ZIP berhasil diekstrak: part11.zip")


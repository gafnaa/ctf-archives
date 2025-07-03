import base64

encoded_data = """
UEsDBBQACQAIAGZ3ZlgEvqDrmwAAAN0AAAAXABwAcGhyZWFrc19wbGFuLnBkZi5wYXJ0MTRVVAkA
A8CE6GXAhOhldXgLAAEE6AMAAAToAwAAKhCv8Ho5I1TZfENnfcarT/3gQrsDqxJ/oAidzEbvaiuJ
DzGdsQShRTZU8OnTwM8z0rpOusv8RovXzLvb099ai+q7J/AHTNDrTK3WxFqaJ1xGSZH1DNQIHkp7
0K8l3JT2Ln1zGJ/GpW2fcFNehGxTlUzyH+cNWThPU1OPWFeDrGEpTtkVUTLO1X9lt14dpG5qD1FR
tC8AbLygCNZQSwcIBL6g65sAAADdAAAAUEsBAh4DFAAJAAgAZndmWAS+oOubAAAA3QAAABcAGAAA
AAAAAQAAALSBAAAAAHBocmVha3NfcGxhbi5wZGYucGFydDE0VVQFAAPAhOhldXgLAAEE6AMAAATo
AwAAUEsFBgAAAAABAAEAXQAAAPwAAAAAAA==
"""

decoded_bytes = base64.b64decode(encoded_data)

with open("part14.zip", "wb") as f:
    f.write(decoded_bytes)

print("File ZIP berhasil diekstrak: part14.zip")


import base64

encoded_data = """
UEsDBBQACQAIAGZ3Zlgub1pG0gAAAN0AAAAWABwAcGhyZWFrc19wbGFuLnBkZi5wYXJ0NlVUCQAD
wIToZcCE6GV1eAsAAQToAwAABOgDAAA9siVDz34UldbdpmALh3n3JpC5DSTu5/F8fuitjI/IDhbW
yDabhamKNp1fsz7hThUnyS6ibIdFtg+YKTm+Tg8Xba1jM0AAf7r/dIGjDciCXGpH2IzkV/7qgbK2
5jIufslNzO0T3tCviOj4q5un2zfP+wPxD8cozyoXPmk53btd+Tyt7eGbQ8r9LaLSAxl+LXrUWe9L
rxeNTDehMoP+oYG2Wp/xW4Xe7cVHSyXYFa1C/6Fs/uZZv2d1N7+jDBCOpFNSUfwMLeNQSZ3js6RU
+DjUWARQSwcILm9aRtIAAADdAAAAUEsBAh4DFAAJAAgAZndmWC5vWkbSAAAA3QAAABYAGAAAAAAA
AAAAALSBAAAAAHBocmVha3NfcGxhbi5wZGYucGFydDZVVAUAA8CE6GV1eAsAAQToAwAABOgDAABQ
SwUGAAAAAAEAAQBcAAAAMgEAAAAA
"""

decoded_bytes = base64.b64decode(encoded_data)

with open("part6.zip", "wb") as f:
    f.write(decoded_bytes)

print("File ZIP berhasil diekstrak: part6.zip")


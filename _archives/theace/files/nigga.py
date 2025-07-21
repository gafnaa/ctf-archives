import base64

# Daftar chunk dari makro
chunks = [
    "aGlkZGVu",         # hidden
    "bWFsaWNpb3Vz",     # malicious
    "Y29kZQ==",         # code
    "aW4=",             # in
    "dGhl",             # the
    "d29yZA==",         # word
    "ZmlsZQ==",         # file
    "aXM=",             # is
    "ZXhlY3V0ZWQ=",     # executed
    "Ynk=",             # by
    "YW4=",             # an
    "aW5qZWN0ZWQ=",     # injected
    "dGVtcGxhdGU=",     # template
    "dHJpZ2dlcmluZw==", # triggering
    "YW4=",             # an
    "YXR0YWNr"          # attack
]

# Decode semua chunk dan gabungkan
decoded_words = [base64.b64decode(chunk).decode('utf-8') for chunk in chunks]
flag = "FLAG{" + ''.join(decoded_words) + "}"

# Tampilkan hasil
print(flag)

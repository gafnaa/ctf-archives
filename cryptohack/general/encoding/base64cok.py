import base64

data = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"

binary_data = bytes.fromhex(data)
flag = base64.b64encode(binary_data).decode('utf-8')

print(flag)
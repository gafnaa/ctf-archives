import base64

cipher = "UVGEFPQOAPQPMOMQEMDOUBTQDITUOTYMWQEYQMBDARQEEUAZMXODKBFATQDA"
try:
    decoded = base64.b64decode(cipher)
    print(decoded)
except Exception as e:
    print(e)

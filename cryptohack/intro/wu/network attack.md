# Network Attacks

Several of the challenges are dynamic and require you to talk to our challenge servers over the network. This allows you to perform man-in-the-middle attacks on people trying to communicate, or directly attack a vulnerable service. To keep things consistent, our interactive servers always send and receive JSON objects.

Such network communication can be made easy in Python with the pwntools module. This is not part of the Python standard library, so needs to be installed with pip using the command line pip install pwntools.

For this challenge, connect to socket.cryptohack.org on port 11112. Send a JSON object with the key buy and value flag.

Connect at socket.cryptohack.org 11112

## Solution

Modify the program. edit the value of JSON.
Here the solver script

```py
import json
from pwn import *

HOST = "socket.cryptohack.org"
PORT = 11112

r = remote(HOST, PORT)


def json_recv():
    line = r.readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)


print(r.readline())
print(r.readline())
print(r.readline())
print(r.readline())

request = {
    "buy": "flag"
}
json_send(request)

response = json_recv()

print(response)
```

## Flag
    crypto{sh0pp1ng_f0r_fl4g5}


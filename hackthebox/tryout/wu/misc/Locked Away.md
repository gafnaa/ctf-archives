# Locked Away
A test! Getting onto the team is one thing, but you must prove your skills to be chosen to represent the best of the best. They have given you the classic - a restricted environment, devoid of functionality, and it is up to you to see what you can do. Can you break open the chest? Do you have what it takes to bring humanity from the brink?

## Solution

try connecting to server..

```sh
$ nc 94.237.53.177 56682

.____                  __              .___    _____
|    |    ____   ____ |  | __ ____   __| _/   /  _  \__  _  _______  ___.__.
|    |   /  _ \_/ ___\|  |/ // __ \ / __ |   /  /_\  \ \/ \/ /\__  \<   |  |
|    |__(  <_> )  \___|    <\  ___// /_/ |  /    |    \     /  / __ \\___  |
|_______ \____/ \___  >__|_ \\___  >____ |  \____|__  /\/\_/  (____  / ____|
        \/          \/     \/    \/     \/          \/             \/\/

The chest lies waiting... os
Invalid command!
The chest lies waiting... import
Invalid command!
The chest lies waiting... ls
You have been locked away...
```

then, open the source code of the program

```py
def open_chest():
    with open('flag.txt', 'r') as f:
        print(f.read())
blacklist = [
    'import', 'os', 'sys', 'breakpoint',
    'flag', 'txt', 'read', 'eval', 'exec',
    'dir', 'print', 'subprocess', '[', ']',
    'echo', 'cat', '>', '<', '"', '\'', 'open'
]
print(banner)
while True:
    command = input('The chest lies waiting... ')
    if any(b in command for b in blacklist):
        print('Invalid command!')
        continue
    try:
        exec(command)
    except Exception:
        print('You have been locked away...')
        exit(1337)
```

If seen from the source code of the program, it means that we can only input something that is only in the `blacklist` variable, otherwise the program will stop. Even though there is an output "Invalid command!" our input will still be executed.

so we can do a command to trick the program.
```sh
blacklist = []
```
Rather than trying to bypass the `blacklist`, we’ll overwrite it.
```sh
blacklist.clear()
```
used to empty the `blacklist` array
```sh
open_chest()
```
access the `open_chest()` function

# Flag
    HTB{bYp4sSeD_tH3_fIlT3r5?_aLw4Ys_b3_c4RefUL!_98d97285e914e5db0aba3497b4b8c41b}
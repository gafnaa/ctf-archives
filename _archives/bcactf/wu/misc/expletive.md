# expletive

## Desc 

oh no! it seems like only some of the characters on my keyboard are working...

nc challs.bcactf.com 38421

## Solve

Given this file

```py
blacklist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def security_check(s):
    return any(c in blacklist for c in s) or s.count('_') > 50

BUFFER_SIZE = 36

while True:
    cmds = input("> ")

    if security_check(cmds):
        print("invalid input")
    else:
        if len(cmds) > BUFFER_SIZE:
            print(open("flag.txt", "r").read())
            break
        else:
            print("nope")
```

So, to get the flag, you need to provide an input that satisfies three conditions:

1. It must not contain any alphanumeric characters (a-z, A-Z, 0-9).
2. The number of underscore characters (`_`) must not exceed 50.
3. The total length of the input string must be greater than 36 characters.

```sh
 python3 -c "print('_' * 37)" | nc challs.bcactf.com 38421                                                         ─╯
> bcactf{fudG3_5hOo7_d4rn100}
```

## Flag
    bcactf{fudG3_5hOo7_d4rn100}
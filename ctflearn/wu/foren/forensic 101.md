# forensic 101

Think the flag is somewhere in there. Would you help me find it? https://mega.nz/#!OHohCbTa!wbg60PARf4u6E6juuvK9-aDRe_bgEL937VO01EImM7c

## Solution

Download the file, then use `strings` command

```
$ strings minion.jpg | grep "flag"
flag{wow!_data_is_cool}
```

## Flag
    CTFLEARN{wow!_data_is_cool}
#!/usr/bin/env python3
import sys
assert sys.stdout.isatty()
flag = open("/flag.txt").read().strip()
to_print = flag + '\r' + ('lmao no flag for you ' * 32)
print(to_print)

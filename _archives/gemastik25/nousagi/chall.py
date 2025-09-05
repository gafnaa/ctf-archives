import randcrack
import random
import os
from libnum import s2n
import signal

seed = os.urandom(12)
wack = randcrack.RandCrack()
random.seed(seed)

print("Find the rabbit!")
for _ in range(624):
    signal.alarm(2) # Dont waste time
    num = int(input(">> "))
    signal.alarm(0)

    wack.submit(num)
    print(random.getrandbits(32))

rabbit = 0
for _ in range(624):
    rabbit ^= random.getrandbits(32) ^ wack.predict_getrandbits(32)
    
if abs(rabbit) < s2n(b'ribbit') % 1337:
    print("You found the rabbit!")
    gift = open('flag.txt').read()
    print(gift)
else:
    print("You didn't find the rabbit, try again!")
    print("Rabbit was:", rabbit)
    exit(1)
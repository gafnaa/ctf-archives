# Stop Drop and Roll
The Fray: The Video Game is one of the greatest hits of the last... well, we don't remember quite how long. Our "computers" these days can't run much more than that, and it has a tendency to get repetitive...

## Solution

try connecting to server..

```sh
$ nc 83.136.252.198 54862
===== THE FRAY: THE VIDEO GAME =====
Welcome!
This video game is very simple
You are a competitor in The Fray, running the GAUNTLET
I will give you one of three scenarios: GORGE, PHREAK or FIRE
You have to tell me if I need to STOP, DROP or ROLL
If I tell you there's a GORGE, you send back STOP
If I tell you there's a PHREAK, you send back DROP
If I tell you there's a FIRE, you send back ROLL
Sometimes, I will send back more than one! Like this:
GORGE, FIRE, PHREAK
In this case, you need to send back STOP-ROLL-DROP!
Are you ready? (y/n) y
Ok then! Let's go!
GORGE
What do you do? STOP
FIRE, GORGE, GORGE, GORGE, FIRE
What do you do? ROLL-STOP-STOP-STOP-ROLL
GORGE, GORGE
What do you do?
```

It seems that this program will continue to ask us to answer questions according to the instructions given. Because we dont know the limit of the number of questions, I made a program to answer the questions automatically.

```py
import nclib
import time

def createResponse(message):
    message = message.split()
    challenge = []
    for item in message:
        if 'GORGE' in item or 'PHREAK' in item or 'FIRE' in item: 
            challenge.append(item)
    challenge = ' '.join(challenge)
    answer = challenge.replace('GORGE', 'STOP').replace('PHREAK', 'DROP').replace('FIRE', 'ROLL').replace(', ','-')
    answer = answer + '\n'
    print(answer)
    return answer

def main():
    server = ('here_ip_server', here_port_server) #adjust ip and port
    nc = nclib.Netcat(connect=server)
    nc.settimeout(None)
    intro = nc.recv_until("Are you ready? (y/n)").decode()
    print(intro)
    nc.send('y\n'.encode())
    while True:
        message = nc.recv_until("What do you do?").decode()
        print(message)
        answer = createResponse(message)
        time.sleep(2)
        nc.send(answer.encode())
    
if __name__ == '__main__':
    main()
```

then, run the program and you will get the flag
```sh
$ python3 solve.py | grep "HTB{"
```

## Flag
    HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_w4Y_oUt!}
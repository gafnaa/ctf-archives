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
    server = ('94.237.63.32', 55143)
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
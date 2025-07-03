from pwn import *

SRVR = "ctf.asgama.online"
PORT = 10000

def main():
    try:
        r = remote(SRVR, PORT)
        
        # Get first line (k value)
        first_line = r.recvline().decode().strip()
        print(f"First line: {first_line}")
        
        # Check if server is sending an error
        if "something error happened" in first_line:
            print("Server error detected")
            r.close()
            return 1
        
        # Get second line (x,y tuple)
        second_line = r.recvline().decode().strip()
        print(f"Second line: {second_line}")
        
        # Check for error in second line
        if "something error happened" in second_line:
            print("Server error detected in response")
            r.close()
            return 1
        
        # Process coordinates
        try:
            xy = second_line[1:-1].split(", ")
            x, y = int(xy[0]), int(xy[1])
            ans = str(y % x).encode()
            r.sendlineafter(b"password: ", ans)
            print(r.recv().decode())
        except Exception as e:
            print(f"Error processing coordinates: {e}")
            print(f"Raw second line: {second_line}")
        
        r.close()
        return 0
        
    except Exception as e:
        print(f"Connection error: {e}")
        return 1

if __name__ == "__main__":
    main()
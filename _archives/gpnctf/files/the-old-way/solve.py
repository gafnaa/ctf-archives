from pwn import *
import subprocess
import string

context.binary = "./the_old_way"

def run_with_input(input_data):
    try:
        result = subprocess.run(
            ["./the_old_way", input_data],
            capture_output=True,
            timeout=1
        )
        return result.stdout.decode(errors="ignore"), result.stderr.decode(errors="ignore")
    except subprocess.TimeoutExpired:
        return "", ""

def main():
    charset = string.printable.strip()
    max_len = 40

    for l in range(1, max_len + 1):
        for guess in itertools.product(charset, repeat=l):
            attempt = ''.join(guess)
            out, err = run_with_input(attempt)
            
            if "flag" in out.lower() or "ctf" in out.lower():
                print(f"[+] Candidate: {attempt}")
                print(out)
                return

if __name__ == "__main__":
    import itertools
    main()

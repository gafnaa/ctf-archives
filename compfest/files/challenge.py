
import logging
import tempfile
import subprocess
from pathlib import Path


def get_module_logger(mod_name: str) -> logging.Logger:
    logger = logging.getLogger(mod_name)
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s [%(name)-12s] %(levelname)-8s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return logger


def check(code: str) -> bool:
    if len(code) < 170 or len(code) > 181:
        return False
    
    if "CF=16" not in code and "dist=0" not in code:
        return False
    
    if sum(int(ch) for ch in code if ch.isdigit()) != 0xCF:
        return False
    
    blacklist = ["use", "std", "include"] # You don't need this
    return all(bl not in code for bl in blacklist)


def main(logger: logging.Logger) -> None:
    print("Enter your code: ")
    code = []
    # In the original, this would be an interactive loop.
    # For automation, we read all available input.
    import sys
    for line in sys.stdin:
        if 'EOF' in line:
            break
        code.append(line.strip())

    code = '\n'.join(code)
    if not check(code):
        print("No cheating! >:(")
        exit(1)
        
    with tempfile.TemporaryDirectory() as wdir:
        try:
            with open(Path(wdir) / "main.rs", 'w') as f:
                f.write(code)
            
            # Use a more robust way to run rustc
            compile_result = subprocess.run(
                ["rustc", "./main.rs"], 
                cwd=wdir, 
                check=True, 
                capture_output=True, 
                text=True,
                timeout=10
            )
        
        except subprocess.CalledProcessError as e:
            print("Invalid code! :(")
            print("Compiler error:", e.stderr)
            exit(1)
        
        except Exception as e:
            print("Unknown error occured! Please notify the CF17 CTF Committee")
            logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno}: {e}")
            exit(1)
        
        try:
            # Execute the compiled program
            out = subprocess.check_output(
                f"timeout 2 ./main", 
                cwd=wdir, 
                shell=True,
                text=True
            )
            # Normalize line endings for comparison
            if out.strip() == code.strip():
                print("Congrats!")
                print("COMPFEST17{QUINES_ARE_FUN_EH}")
            
            else:
                print("Nice try :)")
                print("\nExpected output:\n---\n" + code + "\n---")
                print("\nActual output:\n---\n" + out + "\n---")

        except subprocess.TimeoutExpired:
            print("Your code timed out!")
            exit(1)
        except subprocess.CalledProcessError as e:
            print("Your code failed to run or returned a non-zero exit code.")
            print("Stderr:", e.stderr)
            exit(1)


if __name__ == "__main__":
    # Note: The original script's input loop was changed slightly to
    # work non-interactively for this solver script.
    main(get_module_logger(__name__))

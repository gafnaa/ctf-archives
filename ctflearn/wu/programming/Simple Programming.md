# Simple Programming

Can you help me? I need to know how many lines there are where the number of 0's is a multiple of 3 or the numbers of 1s is a multiple of 2. Please! Here is the file: https://mega.nz/#!7aoVEKhK!BAohJ0tfnP7bISIkbADK3qe1yNEkzjHXLKoJoKmqLys

## Solution

Because there are so many binary files, I made program to calculate it

```py
def count_valid_lines(binary_lines):
    valid_count = 0
    
    for line in binary_lines:
        count_0 = line.count('0')
        count_1 = line.count('1')
        
        if count_0 % 3 == 0 or count_1 % 2 == 0:
            valid_count += 1
    
    return valid_count


with open("data.dat", "r") as file:
    binary_lines = [line.strip() for line in file.readlines()]

result = count_valid_lines(binary_lines)
print("Jumlah baris yang memenuhi kondisi:", result)
```

## Flag
    CTFlearn{6662}
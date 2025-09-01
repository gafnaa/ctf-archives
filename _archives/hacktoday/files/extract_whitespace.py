def analyze_whitespace(line):
    binary = line.replace(' ', '0').replace('\t', '1')
    return binary

with open('salju.txt', 'r') as f:
    lines = f.readlines()
    
for line in lines:
    if line.strip() and all(c in ' \t' for c in line.rstrip()):
        print(analyze_whitespace(line.rstrip()))

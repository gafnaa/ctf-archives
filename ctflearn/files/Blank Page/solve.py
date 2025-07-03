with open("TheMessage.txt", "r", encoding="utf-8") as inp:
    l = list(inp.read())
string = ""
for i in range(0, len(l)):
    if l[i] == " ":
        l[i] = '0'
    else:
        l[i] = '1'
    if i % 8 == 0:
        string += ' '
    string += l[i]

outp = open("output.txt", "w")
outp.write(string)
def reverse_execute(code, final_output):
    values = code.split(" ")
    a = [int(i.split("/")[0]) for i in values]
    b = [int(i.split("/")[1]) for i in values]
    inp = int(final_output)

    for _ in range(1000):
        changed = False
        for i in reversed(range(len(a))):  # dibalik urutannya
            ai, bi = a[i], b[i]
            if (inp * bi) % ai == 0:
                inp = inp * bi // ai
                changed = True
        if not changed:
            break
    return inp

code = open("code.txt", "r").read().strip()
final_output = open("output.txt", "r").read().strip()

result = reverse_execute(code, final_output)
print("Input yang benar adalah:", result)

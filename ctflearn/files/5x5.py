def polybius_decode(coords):
    grid = [
        ['A', 'B', 'C', 'D', 'E'],
        ['F', 'G', 'H', 'I', 'J'],
        ['L', 'M', 'N', 'O', 'P'],
        ['Q', 'R', 'S', 'T', 'U'],
        ['V', 'W', 'X', 'Y', 'Z']
    ]

    result = []
    for coord in coords:
        if '-' in coord:
            r, c = map(int, coord.split('-'))
            letter = grid[r - 1][c - 1]
            result.append(letter)

    return ''.join(result)

raw_input = "1-3,4-4,2-1,{,4-4,2-3,4-5,3-2,1-2,4-3,_,4-5,3-5,}"
# Filter out valid coordinates
tokens = [t for t in raw_input.replace('{', '').replace('}', '').replace('_', '').split(',') if '-' in t]

decoded = polybius_decode(tokens)
print(decoded)

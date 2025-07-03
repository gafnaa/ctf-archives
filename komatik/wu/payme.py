from PIL import Image

img = Image.open('hidden.png')
pixels = img.load()
width, height = img.size

data = bytearray()
for y in range(height):
    for x in range(width):
        r, g, b = pixels[x, y]
        data += bytes([r, g, b])

with open('extracted_main', 'wb') as f:
    f.write(data)

from PIL import Image

def fix_distorted_image(input_path, output_path, shift_per_row=5):
    img = Image.open(input_path)
    width, height = img.size
    fixed_img = Image.new("RGB", (width, height))

    for y in range(height):
        shift = (shift_per_row * y) % width  # wrap around if needed
        row = img.crop((0, y, width, y + 1))
        fixed_row = Image.new("RGB", (width, 1))
        fixed_row.paste(row.crop((shift, 0, width, 1)), (0, 0))
        fixed_row.paste(row.crop((0, 0, shift, 1)), (width - shift, 0))
        fixed_img.paste(fixed_row, (0, y))

    fixed_img.save(output_path)
    print(f"[+] Image fixed and saved to {output_path}")

# Contoh pemakaian:
fix_distorted_image("location.png", "fixed.png")

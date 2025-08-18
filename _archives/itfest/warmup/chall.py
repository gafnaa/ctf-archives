def extract_wav_from_binary(input_file, output_file):
    with open('chall.jpg', 'rb') as f:
        data = f.read()

    # Cari header WAV: 'RIFF....WAVE'
    riff_index = data.find(b'riff')
    if riff_index == -1:
        print("[!] Header 'RIFF' tidak ditemukan.")
        return

    # Ambil ukuran file dari header
    size_bytes = data[riff_index+4:riff_index+8]
    size = int.from_bytes(size_bytes, byteorder='little')

    # Panjang total file WAV = 8 byte header + size dari header
    wav_length = size + 8

    # Ekstrak WAV
    wav_data = data[riff_index:riff_index + wav_length]

    if len(wav_data) != wav_length:
        print(f"[!] Ukuran data tidak cocok. Ditemukan {len(wav_data)} byte, seharusnya {wav_length} byte.")
        return

    with open(output_file, 'wb') as f:
        f.write(wav_data)

    print(f"[✓] WAV berhasil diekstrak ke: {output_file}")


# Contoh penggunaan:
extract_wav_from_binary('input.jpg', 'output.wav')

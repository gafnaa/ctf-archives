def repair_wav_header(filepath):
    with open('output.wav', 'rb') as f:
        data = bytearray(f.read())

    # Perbaiki header 'RIFF' dan 'WAVE' jika diperlukan
    if data[0:4] != b'RIFF':
        print("[!] Header bukan 'RIFF'. Memperbaiki...")
        data[0:4] = b'RIFF'
    
    if data[8:12] != b'WAVE':
        print("[!] Format bukan 'WAVE'. Memperbaiki...")
        data[8:12] = b'WAVE'

    with open("output_repaired.wav", 'wb') as f:
        f.write(data)

    print("[✓] File diperbaiki. Coba cek ulang dengan `file output_repaired.wav`.")

repair_wav_header("output_fixed.wav")

import wave
from PIL import Image
import numpy as np

def solve():
    # 1. Load album.png
    img = Image.open('files/album.png')
    
    # Ensure it's grayscale (L mode)
    if img.mode != 'L':
        img = img.convert('L')

    # 2. Convert to NumPy Array
    img_array = np.array(img)

    # 3. Reverse Normalization
    # img = (img + 32767) / 65535 * 255
    # Reverse:
    # 1. Divide by 255: img_normalized = img_array / 255.0
    # 2. Multiply by 65535: img_scaled = img_normalized * 65535.0
    # 3. Subtract 32767: frames_int16 = img_scaled - 32767
    
    frames_float = (img_array / 255.0) * 65535.0 - 32767
    frames_int16 = frames_float.astype(np.int16)

    # 4. Reshape to 1D Array
    # Original reshape was (441, 444)
    # Total frames = 441 * 444 = 195724
    frames_1d = frames_int16.reshape(-1) # Flatten to 1D

    # 5. Save as WAV
    output_wav_path = 'recovered_flag.wav'
    sample_rate = 44100 # Standard sample rate, assumed from commented line in album.py
    nchannels = 1       # Mono, from album.py
    sampwidth = 2       # 2 bytes per sample (16-bit), from album.py

    with wave.open(output_wav_path, 'wb') as w:
        w.setnchannels(nchannels)
        w.setsampwidth(sampwidth)
        w.setframerate(sample_rate)
        w.writeframes(frames_1d.tobytes()) # Convert numpy array to bytes

    print(f"Recovered WAV file saved to {output_wav_path}")
    print("You can now listen to 'recovered_flag.wav' to find the flag.")

if __name__ == "__main__":
    solve()

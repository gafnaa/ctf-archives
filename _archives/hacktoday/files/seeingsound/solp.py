from mido import MidiFile

def decode_payload_7bit(encoded_data):
    """
    Reconstructs original 8-bit bytes from the 7-bit encoded data format.
    """
    decoded = bytearray()
    # Process the encoded data in pairs of bytes.
    # The first byte of a pair holds the lower 7 bits, and the second holds the MSB.
    for i in range(0, len(encoded_data), 2):
        lower_7_bits = encoded_data[i]
        msb = encoded_data[i+1]
        
        # Reconstruct the original byte by shifting the MSB back to its place
        # and combining it with the lower 7 bits using a bitwise OR.
        original_byte = (msb << 7) | lower_7_bits
        decoded.append(original_byte)
        
    return decoded

# --- Main Decryption Logic ---

input_midi_file = "chall.mid"
output_file = "decrypted_image.png"

try:
    # Load the MIDI file
    mid = MidiFile(input_midi_file)
    
    # This bytearray will store all the data extracted from SysEx messages
    encoded_payload = bytearray()
    
    # The encoding script puts the data in the very first track.
    # We only need to inspect this track.
    if mid.tracks:
        payload_track = mid.tracks[0]
        
        # Iterate through all messages in the track
        for msg in payload_track:
            # We are only interested in 'sysex' messages
            if msg.type == 'sysex':
                # Add the message's data to our payload
                encoded_payload.extend(msg.data)
    
    # Check if we actually found any data
    if encoded_payload:
        print(f"✅ Found {len(encoded_payload)} bytes of encoded data in SysEx messages.")
        
        # Decode the extracted payload
        decoded_data = decode_payload_7bit(encoded_payload)
        
        # Write the fully decoded data to the output file
        with open(output_file, "wb") as f:
            f.write(decoded_data)
            
        print(f"🎉 Successfully decrypted the data and saved it as '{output_file}'.")
    else:
        print("⚠️ No 'sysex' messages containing data were found in the MIDI file.")

except FileNotFoundError:
    print(f"❌ Error: The file '{input_midi_file}' was not found.")
except Exception as e:
    print(f"❌ An unexpected error occurred: {e}")

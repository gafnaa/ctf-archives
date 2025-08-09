from mido import MidiFile, MidiTrack, Message, MetaMessage
import random

def encode_payload_7bit(data):
    encoded = bytearray()
    for byte in data:
        encoded.append(byte & 0x7F)
        encoded.append((byte >> 7) & 0x01)
    return encoded

with open("image.png", "rb") as f:
    flag_bytes = f.read()

challenge_midi = MidiFile()
challenge_midi.ticks_per_beat = 480

payload_track = MidiTrack()
challenge_midi.tracks.append(payload_track)
for i in range(0, len(flag_bytes), 128):
    chunk = flag_bytes[i:i+128]
    encoded_chunk = encode_payload_7bit(chunk)
    payload_track.append(Message('sysex', data=encoded_chunk, time=0))

tempo_control = MidiTrack()
tempo_control.append(MetaMessage('set_tempo', tempo=600000))
challenge_midi.tracks.append(tempo_control)

chord_layer = MidiTrack()
melody_layer = MidiTrack()
bass_layer = MidiTrack()
challenge_midi.tracks += [chord_layer, melody_layer, bass_layer]

ctf_chords = [
    [[60, 64, 67], [62, 65, 69], [59, 63, 67], [55, 60, 64]],
    [[57, 60, 64], [53, 57, 60], [60, 65, 69], [64, 67, 71]],
    [[62, 65, 69], [55, 59, 62], [60, 64, 67], [65, 69, 72]],
]

note_pool = [60, 62, 64, 65, 67, 69, 71, 72, 74, 76, 77, 79]

for level in range(40):
    progression = random.choice(ctf_chords)
    for chord in progression:
        for i, note in enumerate(chord):
            chord_layer.append(Message('note_on', note=note, velocity=50+i*10, time=0))
        for i, note in enumerate(chord):
            chord_layer.append(Message('note_off', note=note, velocity=0, time=1920))
        bass_riff = [
            chord[0] - 24,
            chord[1] - 24,
            chord[2] - 24,
            chord[0] - 24 + 5
        ]
        for bass_note in bass_riff:
            bass_layer.append(Message('note_on', note=bass_note, velocity=random.randint(60, 90), time=0))
            bass_layer.append(Message('note_off', note=bass_note, velocity=0, time=480))
        for _ in range(random.randint(3, 6)):
            melody_note = random.choice(note_pool)
            delay = random.choice([120, 240, 360])
            velocity = random.randint(70, 110)
            melody_layer.append(Message('note_on', note=melody_note, velocity=velocity, time=delay))
            melody_layer.append(Message('note_off', note=melody_note, velocity=0, time=random.randint(240, 480)))

challenge_midi.save("ctf_encoded_challenge.mid")

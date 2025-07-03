import json
from xor_hex import xor_hex_strings

def analyze_keystreams(json_file_path):
    with open(json_file_path, 'r') as f:
        data = json.load(f)

    learning_dataset = data['learning_dataset_for_player']
    
    print("Analyzing keystreams from learning dataset:")
    for sample in learning_dataset:
        plaintext = sample['plaintext_hex']
        ciphertext = sample['ciphertext_hex']
        nonce = sample['nonce_hex']
        counter = sample['counter_int']
        
        try:
            keystream = xor_hex_strings(plaintext, ciphertext)
            print(f"Sample ID: {sample['sample_id']}")
            print(f"  Nonce: {nonce}")
            print(f"  Counter: {counter}")
            print(f"  Keystream: {keystream}")
            print("-" * 30)
        except ValueError as e:
            print(f"Error processing sample {sample['sample_id']}: {e}")
            print("-" * 30)

if __name__ == "__main__":
    analyze_keystreams('crypto-numerology/ctf_challenge_package.json')

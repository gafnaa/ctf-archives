import email
import base64
import os

# --- INSTRUCTIONS ---
# 1. Save the original email source code in a file named "email.txt".
# 2. Make sure "email.txt" is in the same directory as this script.
# 3. Run this script. It will create the image file for you.

email_source_file = 'uto.eml'
output_image_file = 'sleepUto_final.jpg'

try:
    # Read the email source file
    with open(email_source_file, 'r', encoding='utf-8') as f:
        msg = email.message_from_file(f)

    image_payload = None
    
    # Find the image part in the email
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == 'image':
                # Extract the Base64 content
                image_payload = part.get_payload(decode=False)
                break # Stop after finding the first image
    
    if image_payload:
        # Decode the Base64 data
        image_data = base64.b64decode(image_payload)
        
        # Save the image to a file
        with open(output_image_file, 'wb') as f:
            f.write(image_data)
        
        print(f"✅ Success! Image '{output_image_file}' was created.")
        print("\nYou can now run steganalysis on this new file.")

    else:
        print("❌ Error: Could not find an image part in the email source file.")
        print(f"Please make sure '{email_source_file}' contains the full, original email text.")

except FileNotFoundError:
    print(f"❌ Error: The file '{email_source_file}' was not found.")
    print("Please save the original email source as 'email.txt' in the same directory as this script.")

except Exception as e:
    print(f"❌ An unexpected error occurred: {e}")
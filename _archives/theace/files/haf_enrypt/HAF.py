import cv2
import math
import numpy as np
import os
import pyfiglet
from termcolor import colored

class MultiLayerEncryption:
    class Affine:
        def __init__(self, a, b, m):
            self.a = a
            self.b = b
            self.m = m
            
            while math.gcd(self.a, self.m) != 1:
                self.a = (self.a + 1) % self.m
            
            self.inv_a = self.ModInv()
        
        def ModInv(self):
            for i in range(2, self.m):
                if (self.a * i) % self.m == 1:
                    return i
            return 1
        
        def E(self, x):
            return (self.a * x + self.b) % self.m

    @staticmethod
    def matrix_encrypt(img, k=25):
        l, w = img.shape[:2]
        n = max(l, w)
        n = n + 1 if n % 2 else n
        img2 = np.zeros((n, n, 3), dtype=np.uint8)
        img2[:l, :w, :] = img
        
        Mod = 256
        np.random.seed(np.sum(img))  
        d = np.random.randint(256, size=(int(n/2), int(n/2)))
        I = np.identity(int(n/2))
        a = np.mod(-d, Mod)
        
        b = np.mod((k * np.mod(I - a, Mod)), Mod)
        k = np.mod(np.power(k, 127), Mod)
        c = np.mod((I + a), Mod)
        c = np.mod(c * k, Mod)

        A1 = np.concatenate((a, b), axis=1)
        A2 = np.concatenate((c, d), axis=1)
        A = np.concatenate((A1, A2), axis=0)

        Enc1 = (np.matmul(A % Mod, img2[:, :, 0] % Mod)) % Mod
        Enc2 = (np.matmul(A % Mod, img2[:, :, 1] % Mod)) % Mod
        Enc3 = (np.matmul(A % Mod, img2[:, :, 2] % Mod)) % Mod

        Enc1 = np.resize(Enc1, (Enc1.shape[0], Enc1.shape[1], 1))
        Enc2 = np.resize(Enc2, (Enc2.shape[0], Enc2.shape[1], 1))
        Enc3 = np.resize(Enc3, (Enc3.shape[0], Enc3.shape[1], 1))
        Enc = np.concatenate((Enc1, Enc2, Enc3), axis=2)

        key = np.zeros((n + 1, n), dtype=np.uint8)
        key[:n, :n] = A
        key[-1][0] = int(l / Mod)
        key[-1][1] = l % Mod
        key[-1][2] = int(w / Mod)
        key[-1][3] = w % Mod

        return Enc, key

    @staticmethod
    def affine_encrypt(img, a, b, m=256):
        encrypted_img = img.copy()
        height, width = encrypted_img.shape[:2]
        
        affine = MultiLayerEncryption.Affine(a, b, m)
        
        for i in range(height):
            for j in range(width):
                pixel = encrypted_img[i][j]
                r = affine.E(pixel[0])
                g = affine.E(pixel[1])
                b = affine.E(pixel[2])
                encrypted_img[i][j] = [r, g, b]
        
        return encrypted_img

    @staticmethod
    def encrypt_image(image_path, a, b):
        original_img = cv2.imread(image_path)
        
        if original_img is None:
            print(colored(f"Error: Unable to read image file {image_path}", "red"))
            return
        
        print(colored("[+] Performing Affine Encryption...", "yellow"))
        affine_encrypted = MultiLayerEncryption.affine_encrypt(original_img, a, b)
        
        print(colored("[+] Performing Matrix Encryption...", "yellow"))
        matrix_encrypted, key = MultiLayerEncryption.matrix_encrypt(affine_encrypted)
        
        base_name = os.path.splitext(image_path)[0]
        encrypted_img_path = f'{base_name}_encrypted.png'
        key_path = 'key.npy'
        
        cv2.imwrite(encrypted_img_path, matrix_encrypted)
        np.save(key_path, key)
        
        print(colored("Encryption complete!", "green"))
        print(colored(f"Encrypted image saved as: {encrypted_img_path}", "cyan"))
        print(colored(f"Encryption key saved as: {key_path}", "cyan"))
        print(colored(f"Affine parameters used: a={a}, b={b}", "cyan"))

def main():
    banner = pyfiglet.figlet_format("HAF Encryptor")
    print(colored(banner, "blue"))
    
    while True:
        image_path = input(colored("Enter the path to the image you want to encrypt: ", "magenta")).strip()
        if not os.path.isfile(image_path):
            print(colored("Error: File does not exist. Please try again.", "red"))
            continue
        
        while True:
            try:
                a = int(input(colored("Enter value for 'a': ", "magenta")))
                if math.gcd(a, 256) != 1:
                    print(colored("Error: 'a' must be coprime with 256. Please try again.", "red"))
                    continue
                
                b = int(input(colored("Enter value for 'b': ", "magenta")))
                if not (0 <= b <= 255):
                    print(colored("Error: 'b' must be between 0 and 255. Please try again.", "red"))
                    continue
                
                if math.gcd(b, 256) != 1:
                    print(colored("Error: 'b' must be coprime with 256. Please try again.", "red"))
                    continue
                
                if b <= a:
                    print(colored("Error: 'b' must be greater than 'a'. Please try again.", "red"))
                    continue
                
                break
            except ValueError as e:
                print(colored(f"Error: {e}. Please enter valid integers.", "red"))
        
        MultiLayerEncryption.encrypt_image(image_path, a, b)
        break

if __name__ == "__main__":
    main()
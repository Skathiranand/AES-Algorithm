import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
import hashlib

class AESEncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("AES Encryption Tool")

        # Create UI elements
        self.label_key = tk.Label(master, text="Key (min 8 characters):")
        self.label_key.pack()

        self.entry_key = tk.Entry(master, width=32)
        self.entry_key.pack()

        self.label_plaintext = tk.Label(master, text="Plaintext:")
        self.label_plaintext.pack()

        self.entry_plaintext = tk.Entry(master, width=32)
        self.entry_plaintext.pack()

        self.button_encrypt = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.button_encrypt.pack()

        self.label_ciphertext = tk.Label(master, text="Ciphertext:")
        self.label_ciphertext.pack()

        self.text_ciphertext = tk.Text(master, height=5, width=32)
        self.text_ciphertext.pack()

        self.button_decrypt = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.button_decrypt.pack()

        self.label_decrypted = tk.Label(master, text="Decrypted Text:")
        self.label_decrypted.pack()

        self.text_decrypted = tk.Text(master, height=5, width=32)
        self.text_decrypted.pack()

    def derive_key(self, password):
        # Derive a 16-byte key from the password using PBKDF2
        salt = os.urandom(16)  # Generate a random salt
        key = PBKDF2(password, salt, dkLen=16, count=1000000)  # Derive a key
        return key, salt

    def encrypt(self):
        password = self.entry_key.get()
        plaintext = self.entry_plaintext.get()

        if len(password) < 8:
            messagebox.showerror("Error", "Key must be at least 8 characters long.")
            return

        key, salt = self.derive_key(password)
        cipher = AES.new(key, AES.MODE_CBC)
        padded_plaintext = pad(plaintext.encode(), AES.block_size)
        ciphertext = cipher.encrypt(padded_plaintext)

        # Encode IV, salt, and ciphertext to base64
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

        self.text_ciphertext.delete(1.0, tk.END)
        self.text_ciphertext.insert(tk.END, f"IV: {iv}\nSalt: {salt_b64}\nCiphertext: {ciphertext_b64}")

    def decrypt(self):
        password = self.entry_key.get()
        ciphertext_b64 = self.text_ciphertext.get(1.0, tk.END).strip().split('\n')[2].split(': ')[1]
        salt_b64 = self.text_ciphertext.get(1.0, tk.END).strip().split('\n')[1].split(': ')[1]

        if len(password) < 8:
            messagebox.showerror("Error", "Key must be at least 8 characters long.")
            return

        try:
            # Decode the base64 encoded ciphertext and salt
            ciphertext = base64.b64decode(ciphertext_b64)
            salt = base64.b64decode(salt_b64)
            key = PBKDF2(password, salt, dkLen=16, count=1000000)

            iv = base64.b64decode(self.text_ciphertext.get(1.0, tk.END).strip().split('\n')[0].split(': ')[1])

            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)

            self.text_decrypted.delete(1.0, tk.END)
            self.text_decrypted.insert(tk.END, plaintext.decode('utf-8'))
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed. Please check the key and ciphertext.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AESEncryptionApp(root)
    root.mainloop()
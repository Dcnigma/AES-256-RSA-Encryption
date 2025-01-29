import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

# AES key size (256-bit)
AES_KEY_SIZE = 32

# Generate AES key
def generate_aes_key():
    return get_random_bytes(AES_KEY_SIZE)

# Encrypt text with AES
def aes_encrypt(text, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

# Decrypt text with AES
def aes_decrypt(encrypted_text, aes_key):
    try:
        encrypted_data = base64.b64decode(encrypted_text)
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# Encrypt AES key with RSA public key
def rsa_encrypt_aes_key(aes_key, public_key_path):
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = RSA.import_key(key_file.read())
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_key = cipher_rsa.encrypt(aes_key)
        return base64.b64encode(encrypted_key).decode()
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        return None

# Decrypt AES key with RSA private key
def rsa_decrypt_aes_key(encrypted_aes_key, private_key_path):
    try:
        encrypted_key = base64.b64decode(encrypted_aes_key)
        with open(private_key_path, "rb") as key_file:
            private_key = RSA.import_key(key_file.read())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(encrypted_key)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        return None

# GUI Functions
def encrypt_text():
    text = text_input.get("1.0", tk.END).strip()
    if not text:
        messagebox.showwarning("Warning", "Enter text to encrypt")
        return

    public_key_path = filedialog.askopenfilename(title="Select Public Key", filetypes=[("PEM Files", "*.pem")])
    if not public_key_path:
        return

    aes_key = generate_aes_key()
    encrypted_aes_key = rsa_encrypt_aes_key(aes_key, public_key_path)

    if encrypted_aes_key:
        encrypted_text = aes_encrypt(text, aes_key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Encrypted AES Key:\n{encrypted_aes_key}\n\nEncrypted Text:\n{encrypted_text}")

def decrypt_text():
    encrypted_aes_key = aes_key_input.get("1.0", tk.END).strip()
    encrypted_text = encrypted_text_input.get("1.0", tk.END).strip()

    if not encrypted_aes_key or not encrypted_text:
        messagebox.showwarning("Warning", "Enter encrypted text and AES key")
        return

    private_key_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM Files", "*.pem")])
    if not private_key_path:
        return

    aes_key = rsa_decrypt_aes_key(encrypted_aes_key, private_key_path)

    if aes_key:
        decrypted_text = aes_decrypt(encrypted_text, aes_key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Decrypted Text:\n{decrypted_text}")

# GUI Window
root = tk.Tk()
root.title("AES-256 & RSA Encryption")

# Input text field
tk.Label(root, text="Enter Text to Encrypt:").pack()
text_input = tk.Text(root, height=5, width=50)
text_input.pack()

# Encrypt button
tk.Button(root, text="Encrypt", command=encrypt_text).pack()

# AES Key input field for decryption
tk.Label(root, text="Enter Encrypted AES Key:").pack()
aes_key_input = tk.Text(root, height=3, width=50)
aes_key_input.pack()

# Encrypted Text input field for decryption
tk.Label(root, text="Enter Encrypted Text:").pack()
encrypted_text_input = tk.Text(root, height=5, width=50)
encrypted_text_input.pack()

# Decrypt button
tk.Button(root, text="Decrypt", command=decrypt_text).pack()

# Output text field
tk.Label(root, text="Output:").pack()
output_text = tk.Text(root, height=10, width=50)
output_text.pack()

# Run GUI loop
root.mainloop()

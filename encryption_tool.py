# Basic Encryption/Decryption Tool
# Author: Ryan Feneley
# Month: September 2024

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Caesar Cipher
def caesar_encrypt(plaintext, shift):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            shifted = chr((ord(char) + shift - 65) % 26 + 65) if char.isupper() else chr((ord(char) + shift - 97) % 26 + 97)
            encrypted += shifted
        else:
            encrypted += char
    return encrypted

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# Vigenere Cipher
def vigenere_encrypt(plaintext, key):
    encrypted = ""
    key_length = len(key)
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_length].lower()) - 97
            shifted = chr((ord(char) + shift - 65) % 26 + 65) if char.isupper() else chr((ord(char) + shift - 97) % 26 + 97)
            encrypted += shifted
        else:
            encrypted += char
    return encrypted

def vigenere_decrypt(ciphertext, key):
    decrypted = ""
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % key_length].lower()) - 97
            shifted = chr((ord(char) - shift - 65) % 26 + 65) if char.isupper() else chr((ord(char) - shift - 97) % 26 + 97)
            decrypted += shifted
        else:
            decrypted += char
    return decrypted

# AES Encryption/Decryption
def aes_encrypt(plaintext, key):
    cipher = AES.new(key.ljust(16).encode('utf-8'), AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

def aes_decrypt(ciphertext, key):
    raw = base64.b64decode(ciphertext)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key.ljust(16).encode('utf-8'), AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

# Example usage
if __name__ == "__main__":
    message = "Hello, World!"
    caesar_key = 3
    vigenere_key = "KEY"
    aes_key = "mysecretpassword"  # Should be 16, 24, or 32 bytes

    # Caesar Cipher
    caesar_encrypted = caesar_encrypt(message, caesar_key)
    print("Caesar Encrypted:", caesar_encrypted)
    print("Caesar Decrypted:", caesar_decrypt(caesar_encrypted, caesar_key))

    # Vigenère Cipher
    vigenere_encrypted = vigenere_encrypt(message, vigenere_key)
    print("Vigenère Encrypted:", vigenere_encrypted)
    print("Vigenère Decrypted:", vigenere_decrypt(vigenere_encrypted, vigenere_key))

    # AES Encryption
    aes_encrypted = aes_encrypt(message, aes_key)
    print("AES Encrypted:", aes_encrypted)
    print("AES Decrypted:", aes_decrypt(aes_encrypted, aes_key))

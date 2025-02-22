# Encryption Tool
## Overview
This project is a Python-based tool that provides basic encryption and decryption functionality using various algorithms such as Caesar cipher, Vigenère cipher, and AES encryption. It is designed for educational purposes to demonstrate how different encryption techniques work.

## Features
- Supports multiple encryption algorithms: Caesar cipher, Vigenère cipher, and AES.
- Encrypts and decrypts text input based on the selected algorithm.
- AES encryption uses a 256-bit key for secure encryption.
- Easy-to-use command-line interface.

## Requirements
- Python 3.x
- pycryptodome library for AES encryption (can be installed via pip).

## Installation
To install the required dependencies, run:
\\\ash
pip install pycryptodome
\\\

## Usage
1. Clone the repository or download the code.
2. Run the script and select the encryption method:
   \\\ash
   python encryption_tool.py
   \\\
   Example usage:
   - For Caesar cipher encryption:
     \\\ash
     python encryption_tool.py --method caesar --action encrypt --text 
hello
world --shift 3
     \\\
   - For Vigenère cipher decryption:
     \\\ash
     python encryption_tool.py --method vigenere --action decrypt --text ciphertext --key KEY
     \\\
   - For AES encryption:
     \\\ash
     python encryption_tool.py --method aes --action encrypt --text secret
message --key mysecretpassword
     \\\

## How It Works
### Caesar Cipher
- The Caesar cipher shifts each letter of the plaintext by a fixed number of positions (the shift).
- Example: A shift of 3 turns A into D, B into E, and so on.

### Vigenère Cipher
- The Vigenère cipher uses a keyword to shift the letters of the plaintext. Each letter in the plaintext is shifted by the corresponding letter in the keyword.

### AES Encryption
- AES (Advanced Encryption Standard) is a widely used symmetric encryption algorithm. The tool uses AES-256, where a 256-bit key is used to encrypt the data. The text is padded to a block size, and the key is hashed to ensure it's exactly 256 bits.

## Example Output
### Caesar Cipher Encryption:
\\\
Text: hello world
Shift: 3
Encrypted text: khoor zruog
\\\

### AES Encryption:
\\\
Text: secret message
Key: mysecretpassword
Encrypted text: b'\x1b\x94\x93...\xd3'
\\\

## Limitations
- AES encryption requires a strong key for secure encryption.
- Caesar and Vigenère ciphers are basic encryption techniques and are not suitable for serious cryptographic use.
- Ensure that the keys used for AES encryption and decryption are the same.

## License
This project is licensed under the MIT License.

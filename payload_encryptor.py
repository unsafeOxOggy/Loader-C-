#!/usr/bin/env python3
"""
AES Encryption for shellcode files.

Usage:
    python encrypt_shellcode.py <shellcode_file.bin>

Output:
    - <filename>.enc : Encrypted shellcode
    - <filename>.key : Key and IV in hexadecimal format
"""

import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def encrypt_shellcode(input_file: str) -> None:
    # 1. Verify that the file exists
    if not os.path.isfile(input_file):
        print(f"[-] Error: the file '{input_file}' does not exist.")
        sys.exit(1)

    # 2. Read the raw shellcode
    with open(input_file, "rb") as f:
        shellcode = f.read()

    print(f"[*] Shellcode loaded: {len(shellcode)} bytes")

    # 3. Generate a random key (AES-128: 16 bytes)
    key = get_random_bytes(16)
    # 4. Generate a random IV (always 16 bytes for AES)
    iv = get_random_bytes(16)

    # 5. Create the AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 6. Apply PKCS7 padding
    padded_shellcode = pad(shellcode, AES.block_size)

    # 7. Encrypt the payload
    encrypted_shellcode = cipher.encrypt(padded_shellcode)

    # 8. Determine output file names
    base_name = os.path.splitext(os.path.basename(input_file))[0]  # Filename without extension
    enc_file = f"{base_name}.enc"
    key_file = f"{base_name}.key"

    # 9. Save the encrypted shellcode
    with open(enc_file, "wb") as f:
        f.write(encrypted_shellcode)

    print(f"[+] Encrypted shellcode written to: {enc_file}")

    # 10. Save the Key and IV into the .key file
    with open(key_file, "w") as f:
        f.write(f"# Key and IV to decrypt {enc_file}\n")
        f.write(f"# AES-128 in CBC mode\n\n")
        f.write(f"HEX_KEY={key.hex()}\n")
        f.write(f"HEX_IV={iv.hex()}\n")
        f.write(f"\n")
        f.write(f"# Copy-paste formats for different languages:\n\n")
        f.write(f"# Key (Rust):\n")
        f.write(f'const KEY: [u8; 16] = {list(key)};\n\n')
        f.write(f"# IV (Rust):\n")
        f.write(f'const IV: [u8; 16] = {list(iv)};\n\n')
        f.write(f"# Key (C/C++):\n")
        f.write(f'unsigned char key[] = {{ {", ".join(f"0x{b:02x}" for b in key)} }};\n\n')
        f.write(f"# IV (C/C++):\n")
        f.write(f'unsigned char iv[] = {{ {", ".join(f"0x{b:02x}" for b in iv)} }};\n\n')
        f.write(f"# Python:\n")
        f.write(f"key = bytes.fromhex('{key.hex()}')\n")
        f.write(f"iv = bytes.fromhex('{iv.hex()}')\n")

    print(f"[+] Key and IV saved to: {key_file}")

    # 11. Display summary in the console
    print("\n" + "=" * 60)
    print("SUMMARY - INTEGRATE INTO YOUR LOADER:")
    print("=" * 60)
    print(f"Encrypted File   : {enc_file}")
    print(f"Original Size    : {len(shellcode)} bytes")
    print(f"Encrypted Size   : {len(encrypted_shellcode)} bytes")
    print(f"Key Size         : {len(key)} bytes (AES-128)")
    print(f"IV Size          : {len(iv)} bytes")
    print()
    print(f"Key (hex) : {key.hex()}")
    print(f"IV  (hex) : {iv.hex()}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <shellcode_file>")
        sys.exit(1)

    encrypt_shellcode(sys.argv[1])

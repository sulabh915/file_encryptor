# file_encryptor.py
import os
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = 16


def pad(data):
    padding_required = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_required]) * padding_required


def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]


def encrypt_file(file_path, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC)

    with open(file_path, 'rb') as f:
        plaintext = f.read()
    padded = pad(plaintext)
    ciphertext = cipher.encrypt(padded)

    out_file_path = file_path + ".enc"
    with open(out_file_path, 'wb') as f:
        f.write(salt + cipher.iv + ciphertext)

    print(f"[+] File encrypted and saved as {out_file_path}")


def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    key = PBKDF2(password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    out_file_path = file_path.replace(".enc", ".dec")
    with open(out_file_path, 'wb') as f:
        f.write(plaintext)

    print(f"[+] File decrypted and saved as {out_file_path}")


def main():
    parser = argparse.ArgumentParser(description="AES-256 File Encryptor/Decryptor")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help="Operation mode")
    parser.add_argument('file', help="Path to file")
    parser.add_argument('password', help="Password for encryption/decryption")

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print("[-] File does not exist.")
        return

    if args.mode == 'encrypt':
        encrypt_file(args.file, args.password)
    elif args.mode == 'decrypt':
        decrypt_file(args.file, args.password)


if __name__ == '__main__':
    main()


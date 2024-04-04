# EDA - Encryption Decryption Algorithm
# tyjkot

import glob
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from os import urandom
import getpass

# RSA Key Gen
def generate_keys():
    passphrase = getpass.getpass("Enter a passphrase for the private key encryption: ")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    try:
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
            ))

        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        print("Keys generated successfully.")
    except Exception as e:
        print(f"Error saving keys: {e}")

# AES Helper Function
def encrypt_aes(data, key):
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

# AES Helper Function
def decrypt_aes(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data

# Hybrid Encryption Function
def encrypt_file(filename):
    try:
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    except FileNotFoundError:
        print("Public key file not found.")
        return

    symmetric_key = urandom(32)  # AES key
    try:
        with open(filename, 'rb') as f:
            file_data = f.read()
        encrypted_data = encrypt_aes(file_data, symmetric_key)
    except Exception as e:
        print(f"Error encrypting file data: {e}")
        return

    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    with open(filename + '.encrypted', 'wb') as f:
        f.write(encrypted_symmetric_key + encrypted_data)
    print(f"File '{filename}' encrypted successfully.")

# Hybrid Decryption Function
def decrypt_file(encrypted_filename):
    passphrase = getpass.getpass("Enter passphrase for private key: ")
    try:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=passphrase.encode(),
                backend=default_backend()
            )
    except Exception as e:
        print("Error loading private key:", e)
        return

    try:
        with open(encrypted_filename, "rb") as f:
            encrypted_file_data = f.read()
        encrypted_symmetric_key = encrypted_file_data[:256]
        encrypted_data = encrypted_file_data[256:]

        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        original_data = decrypt_aes(encrypted_data, symmetric_key)
    except Exception as e:
        print("Error during decryption:", e)
        return

    decrypted_filename = encrypted_filename.replace(".encrypted", "")
    try:
        with open(decrypted_filename, 'wb') as f:
            f.write(original_data)
        print(f"File decrypted successfully. Saved as '{decrypted_filename}'")
    except Exception as e:
        print(f"Error saving decrypted file: {e}")

# Batch Encrypt
def encrypt_all_txt_files():
    txt_files = glob.glob('*.txt')
    for filename in txt_files:
        if not filename.endswith('.encrypted'):
            encrypt_file(filename)

# Batch Decrypt
def decrypt_all_encrypted_files():
    encrypted_files = glob.glob('*.encrypted')
    for filename in encrypted_files:
        decrypt_file(filename)

# Main
def main():
    choice = input("Generate keys (G), encrypt all .txt files (E), or decrypt all .encrypted files (D)? ").upper()
    if choice == 'G':
        generate_keys()
    elif choice == 'E':
        encrypt_all_txt_files()
    elif choice == 'D':
        decrypt_all_encrypted_files()
    else:
        print("Invalid option. Please choose 'G', 'E', or 'D'.")

# Run
main()

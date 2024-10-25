import os
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import struct

# Generate RSA key pair
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Derive AES key using scrypt
def derive_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,  # 256 bits for AES
        n=2**14,    # CPU/memory cost factor
        r=8,        # Block size
        p=1,        # Parallelization factor
        backend=default_backend()
    )
    return kdf.derive(password)

# Pad plaintext to be a multiple of block size (16 bytes for AES)
def pad(plaintext):
    block_size = 16
    padding_length = block_size - (len(plaintext) % block_size)
    if padding_length == 0:
        padding_length = block_size
    return plaintext + bytes([padding_length] * padding_length)

# Encrypt file using AES-CBC
def encrypt_file(file_path, aes_key):
    iv = os.urandom(16)  # Generate a unique 128-bit IV for this encryption

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Pad plaintext
    padded_plaintext = pad(plaintext)

    # Create AES cipher and encrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return iv, ciphertext

# Encrypt AES key with RSA
def encrypt_aes_key(rsa_public_key, aes_key):
    ciphertext = rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Securely delete a file by overwriting before deletion
def securely_delete(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'ba+', buffering=0) as delfile:
            length = delfile.tell()
        with open(file_path, 'br+') as f:
            f.write(os.urandom(length))  # Overwrite file with random bytes
        os.remove(file_path)  # Now remove the file

# Add HMAC for file integrity check
def create_hmac(aes_key, data):
    h = hmac.HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# Main encryption process for multiple files
def main_encrypt(file_paths):
    private_key, public_key = generate_rsa_keys()

    # Generate a random salt for key derivation
    salt = os.urandom(16)

    # Generate a random password for key derivation
    password = os.urandom(16)

    # Derive the AES key from the password and salt
    aes_key = derive_key(password, salt)

    for file_path in file_paths:
        iv, ciphertext = encrypt_file(file_path, aes_key)  # Get unique AES key and IV
        hmac_signature = create_hmac(aes_key, ciphertext)  # Generate HMAC for integrity check
        encrypted_aes_key = encrypt_aes_key(public_key, aes_key)

        # Structuring the file content: Encrypted AES key (RSA), salt, IV, Ciphertext, HMAC
        enc_file_path = file_path + '.enc'
        with open(enc_file_path, 'wb') as enc_file:
            enc_file.write(struct.pack('>I', len(encrypted_aes_key)))
            enc_file.write(encrypted_aes_key)  # Length-prefixed encrypted AES key
            enc_file.write(salt)  # Write the salt
            enc_file.write(iv)  # IV
            enc_file.write(ciphertext)  # Ciphertext
            enc_file.write(hmac_signature)  # HMAC for integrity

        print(f'File encrypted successfully as {enc_file_path}')

    # Save the private key securely with a random password
    key_password = os.urandom(16)
    with open('private_key.pem', 'wb') as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(key_password)
        ))

    with open('password.txt', 'wb') as pwd_file:
        pwd_file.write(key_password)

    print("Private key and password file generated.")

    # Securely delete original files
    for file_path in file_paths:
        securely_delete(file_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Encrypt files.')
    parser.add_argument('-f', '--files', required=True, nargs='+', help='Files to encrypt')

    args = parser.parse_args()
    main_encrypt(args.files)

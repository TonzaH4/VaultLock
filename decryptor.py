import os
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import struct

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

# Decrypt AES key using RSA
def decrypt_aes_key(rsa_private_key, encrypted_aes_key):
    aes_key = rsa_private_key.decrypt(
        encrypted_aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Remove padding according to PKCS#7
def unpad(padded_data):
    if not padded_data:
        return None  # Return None if data is empty
    padding_length = padded_data[-1]
    if padding_length < 1 or padding_length > 16:
        return None  # Return None on invalid padding
    return padded_data[:-padding_length]

# Decrypt file using AES-CBC
def decrypt_file(ciphertext, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    plaintext = unpad(decrypted_padded)
    return plaintext

# Securely delete a file by overwriting before deletion
def securely_delete(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'ba+', buffering=0) as delfile:
            length = delfile.tell()
        with open(file_path, 'br+') as f:
            f.write(os.urandom(length))  # Overwrite file with random bytes
        os.remove(file_path)  # Now remove the file

# Verify HMAC for file integrity check
def verify_hmac(aes_key, data, expected_hmac):
    h = hmac.HMAC(aes_key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    h.verify(expected_hmac)

# Main decryption process for multiple files
def main_decrypt(enc_file_paths, pem_file, password_file):
    for enc_file_path in enc_file_paths:
        with open(enc_file_path, 'rb') as enc_file:
            # Read length-prefixed encrypted AES key
            aes_key_len = struct.unpack('>I', enc_file.read(4))[0]
            encrypted_aes_key = enc_file.read(aes_key_len)
            salt = enc_file.read(16)  # Read the salt
            iv = enc_file.read(16)  # Read IV

            # Read the rest of the file
            remaining_data = enc_file.read()
            
            # The last 32 bytes of the remaining data is the HMAC
            hmac_signature = remaining_data[-32:]  # HMAC
            ciphertext = remaining_data[:-32]  # The rest is the ciphertext

        with open(password_file, 'rb') as pwd_file:
            password = pwd_file.read()

        with open(pem_file, 'rb') as private_file:
            private_key = serialization.load_pem_private_key(
                private_file.read(),
                password=password,
                backend=default_backend()
            )

        # Decrypt AES key
        aes_key = decrypt_aes_key(private_key, encrypted_aes_key)

        # Verify HMAC integrity before decryption
        verify_hmac(aes_key, ciphertext, hmac_signature)  # Use aes_key for verification

        plaintext = decrypt_file(ciphertext, aes_key, iv)  # Use aes_key for decryption
        
        if plaintext is None:
            print(f'Decryption failed for {enc_file_path}: Padding error or invalid data.')
            continue  # Skip this file if decryption failed

        with open(enc_file_path[:-4], 'wb') as dec_file:
            dec_file.write(plaintext)

        print(f'Decrypted file saved as {enc_file_path[:-4]}')

        # Securely delete the encrypted file after decryption
        securely_delete(enc_file_path)

    # Securely delete the password and private key files after decryption
    securely_delete(password_file)
    securely_delete(pem_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decrypt files.')
    parser.add_argument('-f', '--files', required=True, nargs='+', help='Files to decrypt')
    parser.add_argument('-k', '--pem', required=True, help='Private key PEM file')
    parser.add_argument('-p', '--password', required=True, help='Password file')

    args = parser.parse_args()
    main_decrypt(args.files, args.pem, args.password)

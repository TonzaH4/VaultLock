import os
import argparse
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import struct

# Configure logging
logging.basicConfig(level=logging.INFO)

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
    return rsa_private_key.decrypt(
        encrypted_aes_key,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Remove padding according to PKCS#7
def unpad(padded_data):
    from cryptography.hazmat.primitives import padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# Decrypt file using AES-CBC
def decrypt_file(ciphertext, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(decrypted_padded)

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

# Process files or directory for decryption
def process_files(enc_file_paths, pem_file, password, password_file):
    private_key = None

    # Read private key from the PEM file
    try:
        with open(pem_file, 'rb') as private_file:
            private_key = serialization.load_pem_private_key(
                private_file.read(),
                password=password,
                backend=default_backend()
            )
    except Exception as e:
        logging.error(f'Error reading private key file: {e}')
        return  # Stop processing if the private key can't be read

    success = True  # Flag to track the success of processing

    for enc_file_path in enc_file_paths:
        try:
            if not os.path.exists(enc_file_path):
                logging.error(f'File not found: {enc_file_path}')
                success = False
                continue  # Skip to the next file

            with open(enc_file_path, 'rb') as enc_file:
                aes_key_len = struct.unpack('>I', enc_file.read(4))[0]
                encrypted_aes_key = enc_file.read(aes_key_len)
                salt = enc_file.read(16)  # Read the salt
                iv = enc_file.read(16)  # Read IV

                remaining_data = enc_file.read()
                hmac_signature = remaining_data[-32:]  # HMAC
                ciphertext = remaining_data[:-32]  # The rest is the ciphertext

            # Decrypt AES key
            aes_key = decrypt_aes_key(private_key, encrypted_aes_key)

            # Verify HMAC integrity before decryption
            verify_hmac(aes_key, ciphertext, hmac_signature)

            # Decrypt the file
            plaintext = decrypt_file(ciphertext, aes_key, iv)

            # Save decrypted file
            with open(enc_file_path[:-4], 'wb') as dec_file:
                dec_file.write(plaintext)

            logging.info(f'Decrypted file saved as {enc_file_path[:-4]}')

            # Securely delete the encrypted file after decryption
            securely_delete(enc_file_path)

        except Exception as e:
            logging.error(f'Error processing {enc_file_path}: {e}')
            success = False  # Mark as unsuccessful

    # Securely delete the password and private key files only if all operations are successful
    if success:
        securely_delete(password_file)
        securely_delete(pem_file)
    else:
        logging.info('Key and password files are retained for user review.')

# Main decryption process
def main_decrypt(enc_file_paths, pem_file, password_file):
    # Read password from the password file
    try:
        with open(password_file, 'rb') as pwd_file:
            password = pwd_file.read()
    except Exception as e:
        logging.error(f'Error reading password file: {e}')
        return  # Stop processing if the password file can't be read

    process_files(enc_file_paths, pem_file, password, password_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decrypt files.')
    parser.add_argument('-f', '--files', required=True, nargs='+', help='Files or directory to decrypt')
    parser.add_argument('-k', '--pem', required=True, help='Private key PEM file')
    parser.add_argument('-p', '--password', required=True, help='Password file')

    args = parser.parse_args()

    # Check if the input is a directory or a file
    input_path = args.files[0]
    if os.path.isdir(input_path):
        enc_file_paths = [os.path.join(input_path, f) for f in os.listdir(input_path) if f.endswith('.enc')]
    else:
        enc_file_paths = args.files

    main_decrypt(enc_file_paths, args.pem, args.password)

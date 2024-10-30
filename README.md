# VaultLock

This project provides a secure way to encrypt and decrypt files using AES (Advanced Encryption Standard) in CBC (Cipher Block Chaining) mode and RSA (Rivest–Shamir–Adleman) for key exchange. The implementation ensures that each file is encrypted with a unique AES key and initialization vector (IV).

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [File Structure](#file-structure)
- [How It Works](#how-it-works)
- [Security Considerations](#security-considerations)

## Features

- Encrypt and decrypt files and all contents within directories securely.
- Generates a unique AES key and IV for each file
- Uses RSA for securely exchanging the AES key
- HMAC for integrity verification
- Secure file deletion to prevent data recovery
- Uses Scrypt for key derivation and random salt

## Requirements

- Python 3.x
- `cryptography` library

You can install the required library using pip:

```bash
pip3 install cryptography
```

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/TonzaH4/VaultLock.git
   cd VaultLock
   ```

2. Install the necessary dependencies:
   ```bash
   pip3 install cryptography
   ```

## Usage

### Encrypting Files

To encrypt files, run the `Encryptor.py` script with the paths of the files you wish to encrypt:

```bash
python3 Encryptor.py -f file1.txt file2.txt
```

This will create encrypted files with the `.enc` extension in the same directory.

### Decrypting Files

To decrypt the previously encrypted files, run the `Decryptor.py` script with the paths of the encrypted files and the corresponding private key and password files:

```bash
python3 Decryptor.py -f file1.txt.enc file2.txt.enc -k private_key.pem -p password.txt
```

## File Structure

```
VaultLock/
│
├── Encryptor.py          # Script for encrypting files
├── Decryptor.py          # Script for decrypting files
```

## How It Works

1. **Key Generation**: RSA key pairs are generated to secure the AES keys.
2. **File Encryption**:
   - Each file is encrypted using a unique AES key and IV.
   - The AES key is then encrypted with the RSA public key.
   - An HMAC is created for integrity verification.
3. **File Deletion**: Original files are securely deleted to prevent data recovery.

## Security Considerations

- Each AES key and IV is unique per file to enhance security.
- HMAC ensures the integrity of the encrypted data.
- Secure file deletion reduces the risk of sensitive data recovery.

## License

This project is licensed under the MIT License.

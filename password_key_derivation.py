import os
import sys
import getpass
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

def get_key_from_password(password_provided, salt):
    """
    Derives a cryptographic key from the provided password and salt using PBKDF2 HMAC-SHA256.
    """
    password = password_provided.encode()  # Convert to bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the Fernet key in bytes
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_file(file_name, password):
    """
    Encrypts a file using AES encryption with a key derived from the provided password and a random salt.
    """
    # Generate a random salt
    salt = os.urandom(16)

    # Derive the key using the password and the salt
    key = get_key_from_password(password, salt)
    fernet = Fernet(key)

    try:
        with open(file_name, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)

        encrypted_file_name = file_name + '.encrypted'
        with open(encrypted_file_name, 'wb') as encrypted_file:
            # Prepend the salt to the encrypted data
            encrypted_file.write(salt + encrypted)
        print(f"File '{file_name}' encrypted successfully as '{encrypted_file_name}'.")
    except FileNotFoundError:
        print(f"File '{file_name}' not found.")
    except Exception as e:
        print(f"An error occurred during encryption: {e}")

def decrypt_file(encrypted_file_name, password):
    """
    Decrypts an encrypted file using AES decryption with a key derived from the provided password and the salt extracted from the file.
    """
    try:
        with open(encrypted_file_name, 'rb') as enc_file:
            # Read the salt and the encrypted data
            salt = enc_file.read(16)  # Assuming the salt is 16 bytes
            encrypted = enc_file.read()

        # Derive the key using the password and the extracted salt
        key = get_key_from_password(password, salt)
        fernet = Fernet(key)

        decrypted = fernet.decrypt(encrypted)

        if encrypted_file_name.endswith('.encrypted'):
            decrypted_file_name = encrypted_file_name[:-10]  # Remove '.encrypted' extension
        else:
            decrypted_file_name = encrypted_file_name + '.decrypted'

        with open(decrypted_file_name, 'wb') as dec_file:
            dec_file.write(decrypted)
        print(f"File '{encrypted_file_name}' decrypted successfully as '{decrypted_file_name}'.")
    except FileNotFoundError:
        print(f"File '{encrypted_file_name}' not found.")
    except InvalidToken:
        print("Incorrect password or corrupted file.")
    except Exception as e:
        print(f"An error occurred during decryption: {e}")

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  To encrypt a file: python script.py -e <filename>")
        print("  To decrypt a file: python script.py -d <filename.encrypted>")
        sys.exit(1)

    option = sys.argv[1]
    if option == '-e':
        file_name = sys.argv[2]
        password = getpass.getpass("Enter password for encryption: ")
        encrypt_file(file_name, password)
    elif option == '-d':
        encrypted_file_name = sys.argv[2]
        password = getpass.getpass("Enter password for decryption: ")
        decrypt_file(encrypted_file_name, password)
    else:
        print("Invalid option. Use '-e' to encrypt or '-d' to decrypt.")
        sys.exit(1)

if __name__ == '__main__':
    main()
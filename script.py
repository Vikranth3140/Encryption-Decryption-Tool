import os
import sys
import getpass
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key():
    """
    Generates a new Fernet key and saves it to 'secret.key' file.
    """
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)
    print("Encryption key generated and saved to 'secret.key'.")

def load_key():
    """
    Loads the Fernet key from 'secret.key' file.
    """
    try:
        return open('secret.key', 'rb').read()
    except FileNotFoundError:
        print("Key file 'secret.key' not found. Please generate a key first using '-g' option.")
        sys.exit(1)

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

def encrypt_file(file_name, key_method):
    """
    Encrypts a file using the specified key method ('key' or 'password').
    """
    try:
        with open(file_name, 'rb') as file:
            original = file.read()
    except FileNotFoundError:
        print(f"File '{file_name}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
        sys.exit(1)

    if key_method == 'key':
        # Use stored Fernet key
        key = load_key()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(original)
        encrypted_file_name = file_name + '.encrypted'
        with open(encrypted_file_name, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)
        print(f"File '{file_name}' encrypted successfully as '{encrypted_file_name}' using stored key.")
    elif key_method == 'password':
        # Use password-based key derivation
        password = getpass.getpass("Enter password for encryption: ")
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            print("Passwords do not match.")
            sys.exit(1)
        salt = os.urandom(16)
        key = get_key_from_password(password, salt)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(original)
        encrypted_file_name = file_name + '.encrypted'
        with open(encrypted_file_name, 'wb') as encrypted_file:
            # Prepend the salt to the encrypted data
            encrypted_file.write(salt + encrypted)
        print(f"File '{file_name}' encrypted successfully as '{encrypted_file_name}' using password-based key derivation.")
    else:
        print("Invalid key method. Use 'key' or 'password'.")
        sys.exit(1)

def decrypt_file(encrypted_file_name, key_method):
    """
    Decrypts an encrypted file using the specified key method ('key' or 'password').
    """
    try:
        with open(encrypted_file_name, 'rb') as enc_file:
            encrypted_data = enc_file.read()
    except FileNotFoundError:
        print(f"File '{encrypted_file_name}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while reading the encrypted file: {e}")
        sys.exit(1)

    if key_method == 'key':
        # Use stored Fernet key
        key = load_key()
        fernet = Fernet(key)
        try:
            decrypted = fernet.decrypt(encrypted_data)
        except InvalidToken:
            print("Decryption failed. Invalid key or corrupted file.")
            sys.exit(1)
        decrypted_file_name = encrypted_file_name.replace('.encrypted', '.decrypted')
        with open(decrypted_file_name, 'wb') as dec_file:
            dec_file.write(decrypted)
        print(f"File '{encrypted_file_name}' decrypted successfully as '{decrypted_file_name}' using stored key.")
    elif key_method == 'password':
        # Use password-based key derivation
        # Read the salt and the encrypted data
        salt = encrypted_data[:16]  # First 16 bytes are the salt
        encrypted = encrypted_data[16:]
        password = getpass.getpass("Enter password for decryption: ")
        key = get_key_from_password(password, salt)
        fernet = Fernet(key)
        try:
            decrypted = fernet.decrypt(encrypted)
        except InvalidToken:
            print("Decryption failed. Incorrect password or corrupted file.")
            sys.exit(1)
        decrypted_file_name = encrypted_file_name.replace('.encrypted', '.decrypted')
        with open(decrypted_file_name, 'wb') as dec_file:
            dec_file.write(decrypted)
        print(f"File '{encrypted_file_name}' decrypted successfully as '{decrypted_file_name}' using password-based key derivation.")
    else:
        print("Invalid key method. Use 'key' or 'password'.")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  To generate a key: python script.py -g")
        print("  To encrypt a file with stored key: python script.py -e -k <filename>")
        print("  To encrypt a file with password: python script.py -e -p <filename>")
        print("  To decrypt a file with stored key: python script.py -d -k <filename>.encrypted")
        print("  To decrypt a file with password: python script.py -d -p <filename>.encrypted")
        sys.exit(1)

    option = sys.argv[1]
    if option == '-g':
        generate_key()
    elif option == '-e' or option == '-d':
        if len(sys.argv) != 4:
            print("Please provide the key method and filename.")
            sys.exit(1)
        key_option = sys.argv[2]
        if key_option == '-k':
            key_method = 'key'
        elif key_option == '-p':
            key_method = 'password'
        else:
            print("Invalid key method option. Use '-k' for stored key or '-p' for password-based key derivation.")
            sys.exit(1)
        file_name = sys.argv[3]
        if option == '-e':
            encrypt_file(file_name, key_method)
        elif option == '-d':
            decrypt_file(file_name, key_method)
    else:
        print("Invalid option.")
        sys.exit(1)

if __name__ == '__main__':
    main()
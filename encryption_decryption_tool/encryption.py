import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def generate_key():
    """Generates a new key and saves it to 'secret.key'."""
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("New secret key generated and saved to 'secret.key'.")

def load_key():
    """Loads the key from the 'secret.key' file, or generates a new one if not found."""
    key_path = "secret.key"
    if not os.path.exists(key_path):
        print("Secret key not found. Generating a new key...")
        generate_key()
    return open(key_path, "rb").read()

def get_key_from_password(password, salt=None):
    """
    Derives a cryptographic key from the provided password and salt.
    If no salt is provided, generates a new one.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a new salt if none is provided

    # Ensure the password is treated as a string and encoded consistently
    if isinstance(password, str):
        password_bytes = password.encode()  # Convert password to bytes if it's a string
    else:
        password_bytes = password  # If it's already bytes, use as-is

    # Log the password and salt for debugging
    print(f"Password (original): {password}")
    print(f"Password (encoded as bytes): {password_bytes}")
    print(f"Salt used (hex): {salt.hex()}")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))  # Derive the key
    print(f"Derived key (encoded): {key}")

    return key, salt  # Return both the key and the salt

def encrypt_file(file_name, key):
    """
    Encrypts the file with the given key.
    If the key is password-derived, the salt is stored at the beginning of the file.
    """
    with open(file_name, "rb") as f:
        data = f.read()

    fernet = Fernet(key[0] if isinstance(key, tuple) else key)
    encrypted = fernet.encrypt(data)

    encrypted_file_name = file_name + ".encrypted"
    with open(encrypted_file_name, "wb") as f:
        if isinstance(key, tuple):
            salt = key[1]  # Extract the salt
            f.write(salt)  # Write the salt at the beginning of the file
            print(f"Encryption salt (hex): {salt.hex()}")  # Print the salt
        f.write(encrypted)  # Write the encrypted data

    print(f"Encryption key (derived): {key[0] if isinstance(key, tuple) else key}")
    print(f"File '{file_name}' encrypted successfully.")

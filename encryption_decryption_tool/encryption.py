# encryption.py
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def generate_key():
    """Generates a new Fernet key and saves it to 'secret.key' file."""
    key = Fernet.generate_key()
    key_path = os.path.join(os.path.dirname(__file__), "secret.key")
    with open(key_path, "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    """Loads the key from the 'secret.key' file, generates one if it doesn't exist."""
    key_path = os.path.join(os.path.dirname(__file__), "secret.key")
    if not os.path.exists(key_path):
        print("Secret key not found. Generating a new key...")
        return generate_key()  # Generate a new key if it doesn't exist
    with open(key_path, "rb") as key_file:
        key = key_file.read()
    return key

def encrypt_file(file_name, key):
    """
    Encrypts the file with the given key.
    """
    with open(file_name, "rb") as f:
        data = f.read()

    # Encrypt the file content
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)

    # If we are using a password-derived key, we need to store the salt
    encrypted_file_name = file_name + ".encrypted"
    with open(encrypted_file_name, "wb") as f:
        # If the key is derived from a password, append the salt to the start of the file
        if isinstance(key, tuple):
            salt = key[1]  # Extract the salt if key is a tuple (key, salt)
            f.write(salt)  # Store salt at the beginning of the file
            f.write(encrypted)  # Write the encrypted content
        else:
            f.write(encrypted)

def get_key_from_password(password, salt=None):
    """
    Derives a cryptographic key from the provided password and optional salt.

    Args:
        password (str): The password to derive the key from.
        salt (bytes, optional): A salt value. If None, a new salt will be generated.

    Returns:
        tuple: A tuple of (key, salt) where key is the derived key and salt is the salt used.
    """
    if not salt:
        salt = os.urandom(16)  # Generate a new salt if not provided
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

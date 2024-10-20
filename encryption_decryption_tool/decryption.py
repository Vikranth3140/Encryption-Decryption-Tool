# decryption.py
import os
from cryptography.fernet import Fernet, InvalidToken
from encryption_decryption_tool.encryption import get_key_from_password

def load_key():
    """Loads the key from the 'secret.key' file."""
    key_path = os.path.join(os.path.dirname(__file__), "secret.key")
    with open(key_path, "rb") as key_file:
        key = key_file.read()
    return key

def decrypt_file(file_name, key):
    """
    Decrypts the file with the given key.
    """
    with open(file_name, "rb") as f:
        # If using a password-derived key, the salt is stored at the beginning of the file
        if isinstance(key, tuple):
            salt = f.read(16)  # Assuming the salt is 16 bytes
            encrypted = f.read()  # Read the rest of the encrypted data
            key, _ = get_key_from_password(key[0], salt)  # Derive the key again using the salt
        else:
            encrypted = f.read()

    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken:
        raise ValueError("Decryption failed. Invalid key or corrupted file.")

    # Write the decrypted content back to a file
    decrypted_file_name = file_name.replace(".encrypted", ".decrypted")
    with open(decrypted_file_name, "wb") as f:
        f.write(decrypted)


def retrieve_salt_from_file(file_name):
    """
    Reads the salt from the encrypted file (if stored at the beginning of the file).
    Assumes the salt is the first 16 bytes of the encrypted file.
    
    Args:
        file_name (str): The name of the encrypted file.
    
    Returns:
        bytes: The extracted salt from the encrypted file.
    """
    try:
        with open(file_name, "rb") as encrypted_file:
            return encrypted_file.read(16)  # Assuming the first 16 bytes are the salt
    except FileNotFoundError:
        raise FileNotFoundError(f"File '{file_name}' not found.")
    except Exception as e:
        raise ValueError(f"Failed to retrieve salt from file: {str(e)}")

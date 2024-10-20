# decryption.py
import os
from cryptography.fernet import Fernet, InvalidToken

def load_key():
    """Loads the key from the 'secret.key' file."""
    key_path = os.path.join(os.path.dirname(__file__), "secret.key")
    with open(key_path, "rb") as key_file:
        key = key_file.read()
    return key

def decrypt_file(encrypted_file_name, key):
    """Decrypts the given file using Fernet encryption."""
    fernet = Fernet(key)
    with open(encrypted_file_name, "rb") as enc_file:
        encrypted = enc_file.read()
    try:
        decrypted = fernet.decrypt(encrypted)
        with open(encrypted_file_name.replace(".encrypted", ".decrypted"), "wb") as dec_file:
            dec_file.write(decrypted)
    except InvalidToken:
        raise ValueError("Decryption failed. Invalid key or corrupted file.")

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

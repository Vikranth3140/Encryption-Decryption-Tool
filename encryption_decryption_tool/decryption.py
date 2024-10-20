import os
from cryptography.fernet import Fernet, InvalidToken
from encryption_decryption_tool.encryption import get_key_from_password


def load_key():
    """Loads the key from the 'secret.key' file."""
    return open("secret.key", "rb").read()


def decrypt_file(file_name, key):
    """Decrypts the file with the given key."""
    with open(file_name, "rb") as f:
        if isinstance(key, tuple):
            salt = f.read(16)  # Extract the salt from the beginning of the file
            encrypted = f.read()  # Read the remaining encrypted data
            key, _ = get_key_from_password(key[0], salt)  # Derive the key again using the salt
        else:
            encrypted = f.read()  # For key-based encryption, just read the encrypted data

    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken:
        raise ValueError("Decryption failed. Invalid key or corrupted file.")

    decrypted_file_name = file_name.replace(".encrypted", ".decrypted")
    with open(decrypted_file_name, "wb") as f:
        f.write(decrypted)

    print(f"File '{file_name}' decrypted successfully.")

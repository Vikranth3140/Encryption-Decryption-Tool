# encryption_decryption_tool/__init__.py
from .encryption import generate_key, encrypt_file, load_key, get_key_from_password
from .decryption import decrypt_file, retrieve_salt_from_file

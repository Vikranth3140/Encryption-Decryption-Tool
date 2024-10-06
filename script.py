from cryptography.fernet import Fernet
import sys
import os

def generate_key():
    """
    Generates a new AES encryption key and saves it to 'secret.key' file.
    """
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)
    print("Encryption key generated and saved to 'secret.key'.")

def load_key():
    """
    Loads the AES encryption key from 'secret.key' file.
    """
    return open('secret.key', 'rb').read()

def encrypt_file(file_name):
    """
    Encrypts a file using the AES key.
    """
    key = load_key()
    fernet = Fernet(key)

    with open(file_name, 'rb') as file:
        original = file.read()

    encrypted = fernet.encrypt(original)

    with open(file_name + '.encrypted', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
    print(f"File '{file_name}' encrypted successfully.")

def decrypt_file(encrypted_file_name):
    """
    Decrypts an encrypted file using the AES key.
    """
    key = load_key()
    fernet = Fernet(key)

    with open(encrypted_file_name, 'rb') as enc_file:
        encrypted = enc_file.read()

    decrypted = fernet.decrypt(encrypted)

    decrypted_file_name = encrypted_file_name.replace('.encrypted', '.decrypted')
    with open(decrypted_file_name, 'wb') as dec_file:
        dec_file.write(decrypted)
    print(f"File '{encrypted_file_name}' decrypted successfully.")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  To generate a key: python script.py -g")
        print("  To encrypt a file: python script.py -e <filename>")
        print("  To decrypt a file: python script.py -d <filename.encrypted>")
        sys.exit(1)

    option = sys.argv[1]
    if option == '-g':
        generate_key()
    elif option == '-e':
        if len(sys.argv) != 3:
            print("Please provide the filename to encrypt.")
            sys.exit(1)
        file_name = sys.argv[2]
        encrypt_file(file_name)
    elif option == '-d':
        if len(sys.argv) != 3:
            print("Please provide the filename to decrypt.")
            sys.exit(1)
        encrypted_file_name = sys.argv[2]
        decrypt_file(encrypted_file_name)
    else:
        print("Invalid option.")
        sys.exit(1)

if __name__ == '__main__':
    main()
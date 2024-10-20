import argparse
from encryption_decryption_tool.encryption import encrypt_file, generate_key, load_key, get_key_from_password
from encryption_decryption_tool.decryption import decrypt_file


def check_password_strength(password):
    """Checks if the password meets complexity requirements."""
    import re
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


def get_password_from_user(confirm=False):
    """Prompts the user to input a password, optionally confirming it."""
    password = input("Enter password: ")

    if not check_password_strength(password):
        print("Password must be at least 8 characters long and include uppercase, lowercase, a number, and a special character.")
        return get_password_from_user(confirm)  # Recursively prompt until a valid password is entered

    if confirm:
        confirm_password = input("Confirm password: ")
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            return get_password_from_user(confirm)  # Recursively prompt until passwords match

    return password


def main():
    parser = argparse.ArgumentParser(description="Encrypt and Decrypt files using CLI")
    
    # Subcommands for encrypt and decrypt
    subparsers = parser.add_subparsers(dest="command")

    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("--file", required=True, help="File to encrypt")
    encrypt_parser.add_argument("--method", choices=["key", "password"], required=True, help="Encryption method (key/password)")

    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("--file", required=True, help="File to decrypt")
    decrypt_parser.add_argument("--method", choices=["key", "password"], required=True, help="Decryption method (key/password)")

    args = parser.parse_args()

    if args.command == "encrypt":
        if args.method == "key":
            key = load_key()
            encrypt_file(args.file, key)
            print(f"File '{args.file}' encrypted successfully using a key!")
        elif args.method == "password":
            password = get_password_from_user(confirm=True)
            key, salt = get_key_from_password(password)
            encrypt_file(args.file, (key, salt))
            print(f"File '{args.file}' encrypted successfully using a password!")

    elif args.command == "decrypt":
        if args.method == "key":
            key = load_key()
            decrypt_file(args.file, key)
            print(f"File '{args.file}' decrypted successfully using a key!")
        elif args.method == "password":
            password = get_password_from_user()
            with open(args.file, "rb") as f:
                salt = f.read(16)  # Read the salt from the file
            key, _ = get_key_from_password(password, salt)
            decrypt_file(args.file, (key, salt))
            print(f"File '{args.file}' decrypted successfully using a password!")


if __name__ == "__main__":
    main()

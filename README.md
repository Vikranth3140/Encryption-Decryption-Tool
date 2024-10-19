# File Encryption and Decryption Tool

## Introduction

This Python tool provides a flexible way to encrypt and decrypt files. It supports two methods of key management:

1. **Stored Key Method**: Uses a securely generated key saved to a file (`secret.key`).
2. **Password-Based Key Derivation**: Derives the encryption key from a user-provided password using PBKDF2 HMAC-SHA256 with a unique, random salt.

By combining both methods into a single script, users can choose the approach that best fits their needs, balancing convenience and security.

---

## Features

- **Flexible Key Management**: Choose between a stored key or password-derived key.
- **Strong Encryption**: Utilizes the Fernet symmetric encryption, which is built on AES 128 in CBC mode and uses HMAC for authentication.
- **Password Strength Enforcement**: Ensures that passwords meet complexity requirements for enhanced security.
- **Unique Salt Generation**: For password-based encryption, a new random salt is generated for each file.
- **Password Confirmation**: Prevents accidental typos by requiring password confirmation during encryption.
- **Cross-Platform**: Works on any system with Python 3.x installed.
- **Error Handling**: Provides informative messages for common errors and issues.

---

## Requirements

- **Python 3.x**
- **cryptography Library**

---

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/Vikranth3140/Encryption-Decryption-Tool.git
   ```

2. **Install Required Libraries**

   Install the `cryptography` library using pip:

   ```bash
   pip install cryptography
   ```

---

## Usage Instructions

The script is executed via the command line and supports the following operations:

- Generate a key (for the stored key method)
- Encrypt a file
- Decrypt a file

### **Command-Line Options**

- `-g`: Generate a Fernet key and save it to `secret.key`.
- `-e`: Encrypt a file.
- `-d`: Decrypt a file.
- `-k`: Use the stored key method.
- `-p`: Use the password-based key derivation method.

### **1. Generate a Fernet Key (Stored Key Method)**

Before encrypting files using the stored key method, you need to generate a key.

```bash
python script.py -g
```

**Output:**

```
Encryption key generated and saved to 'secret.key'.
```

- **Note:** Keep the `secret.key` file secure. If it's lost or compromised, encrypted data cannot be decrypted or may be at risk.

### **2. Encrypt a File**

#### **Using Stored Key Method**

```bash
python script.py -e -k <filename>
```

- **`<filename>`**: The path to the file you want to encrypt.
- The script uses the key stored in `secret.key`.

#### **Using Password-Based Key Derivation**

```bash
python script.py -e -p <filename>
```

- The script will prompt you to enter and confirm a password.

## Password Strength Requirements

- At least **8 characters** long.
- Contains at least one **uppercase letter** (`A-Z`).
- Contains at least one **lowercase letter** (`a-z`).
- Contains at least one **digit** (`0-9`).
- Contains at least one **special character** (e.g., `!@#$%^&*()`).
- If the password doesn't meet these requirements, the script will prompt you to enter a stronger password.
- A unique, random salt is generated and prepended to the encrypted file.

**Example:**

```bash
python script.py -e -p confidential.txt
```

**Output:**

```
Enter password for encryption:
Password must be at least 8 characters long.
Please choose a stronger password.
Enter password for encryption:
Confirm password:
File 'confidential.txt' encrypted successfully as 'confidential.txt.encrypted' using password-based key derivation.
```

### **3. Decrypt a File**

#### **Using Stored Key Method**

```bash
python script.py -d -k <filename>.encrypted
```

- **`<filename>.encrypted`**: The path to the encrypted file.
- The script uses the key stored in `secret.key`.

#### **Using Password-Based Key Derivation**

```bash
python script.py -d -p <filename>.encrypted
```

- The script will prompt you to enter the password used during encryption.
- The salt is read from the encrypted file.

**Example:**

```bash
python script.py -d -p confidential.txt.encrypted
```

**Output:**

```
Enter password for decryption:
File 'confidential.txt.encrypted' decrypted successfully as 'confidential.txt.decrypted' using password-based key derivation.
```

---

## Examples

### **Encrypting and Decrypting with Stored Key**

1. **Generate a Key**

   ```bash
   python script.py -g
   ```

2. **Encrypt a File**

   ```bash
   python script.py -e -k report.pdf
   ```

3. **Decrypt the File**

   ```bash
   python script.py -d -k report.pdf.encrypted
   ```

### **Encrypting and Decrypting with Password**

1. **Encrypt a File**

   ```bash
   python script.py -e -p notes.txt
   ```

   - Enter and confirm your password when prompted.
   - Ensure your password meets the complexity requirements.

2. **Decrypt the File**

   ```bash
   python script.py -d -p notes.txt.encrypted
   ```

   - Enter the password used during encryption.

---

## Security Considerations

- **Stored Key Method:**

  - **Key Security:** The `secret.key` file must be kept secure. If an unauthorized person accesses this file, they can decrypt any files encrypted with it.
  - **Key Backup:** Losing the `secret.key` file means losing access to all encrypted data. Ensure you have a secure backup.

- **Password-Based Key Derivation:**

  - **Password Strength Enforcement:** The script enforces strong passwords to enhance security.
    - Passwords must meet the complexity requirements outlined above.
    - This reduces the risk of unauthorized access due to weak passwords.
  - **Password Recovery:** If you forget your password, the encrypted data cannot be recovered.
  - **Salt Usage:** A unique 16-byte random salt is generated for each encryption operation, enhancing security.

- **General Recommendations:**

  - **Data Backup:** Always keep backups of your original files before encryption.
  - **Test the Script:** Try encrypting and decrypting test files to familiarize yourself with the process.
  - **Legal Compliance:** Ensure that you comply with all relevant laws and regulations regarding data encryption in your jurisdiction.

---

## Limitations

- **Large Files:** The script reads the entire file into memory. Encrypting very large files may lead to high memory usage.
- **Single-File Processing:** The script processes one file at a time. Batch processing is not implemented.
- **No Integrity Verification:** The script does not include a mechanism to verify the integrity of the decrypted data (e.g., checksums or MACs).

---

## Future Enhancements

- **Chunked File Processing:**

  - Modify the script to handle files in chunks, reducing memory usage and allowing encryption of large files.

- **Integrity Verification:**

  - Include a Message Authentication Code (MAC) or checksum to verify data integrity upon decryption.

- **Graphical User Interface (GUI):**

  - Develop a user-friendly GUI using frameworks like Tkinter or PyQt5.

- **Batch Processing:**

  - Add functionality to encrypt or decrypt multiple files or entire directories.

---

## Troubleshooting

- **"Password must contain at least one uppercase letter.":**

  - Ensure your password includes at least one uppercase letter (`A-Z`).

- **"Password must be at least 8 characters long.":**

  - Enter a password that is at least 8 characters in length.

- **"Passwords do not match":**

  - Re-enter the same password during the confirmation prompt to avoid typos.

- **"Incorrect password or corrupted file":**

  - Ensure you're using the correct password.
  - Verify that the file was not altered or corrupted.

- **"Decryption failed. Invalid key or corrupted file":**

  - Confirm that you're using the correct key file.
  - Check if the encrypted file is intact and was not modified.

- **"Key file 'secret.key' not found":**

  - Ensure you've generated the key using `python script.py -g` before encrypting or decrypting with the stored key method.

---

## License

This script is licensed under the [MIT License](LICENSE).

---

## Acknowledgments

- **Cryptography Library:** Utilizes the [cryptography](https://cryptography.io/en/latest/) library for secure encryption and key management.
- **Fernet Encryption:** Implements Fernet symmetric encryption, ensuring that data is encrypted and authenticated.

---

Thank you for using this encryption tool. Your feedback and contributions are welcome!

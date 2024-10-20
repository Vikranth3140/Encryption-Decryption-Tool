import os
import sys
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox as msg, simpledialog

# Add the parent directory to sys.path to import from encryption_decryption_tool
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from encryption_decryption_tool import generate_key, load_key, encrypt_file, decrypt_file, get_key_from_password, retrieve_salt_from_file

# Initialize the CustomTkinter app
app = ctk.CTk()

def CenterWindowToDisplay(Screen, width, height, scale_factor=1.0):
    """
    Centers the application window on the main display/monitor.
    """
    screen_width = Screen.winfo_screenwidth()
    screen_height = Screen.winfo_screenheight()
    x = int(((screen_width / 2) - (width / 2)) * scale_factor)
    y = int(((screen_height / 2) - (height / 1.5)) * scale_factor)
    return f"{width}x{height}+{x}+{y}"

# Set the geometry of the window and the title
app.geometry(CenterWindowToDisplay(app, 650, 400, app._get_window_scaling()))
app.title("Encryption and Decryption")

# Create the heading frame and label
heading_frame = ctk.CTkFrame(app)
heading_frame.pack(anchor=ctk.N, fill=ctk.X)
heading_label = ctk.CTkLabel(
    heading_frame, text="Encryption and Decryption", font=("Helvetica", 30)
)
heading_label.pack(anchor=ctk.CENTER, fill=ctk.X)

# File Browsing functions for Encryption and Decryption
def Encrypt_browse_key():
    """Open a file dialog to select a file for encryption with a secret key."""
    encryptfilename.delete(0, ctk.END)
    filename = ctk.filedialog.askopenfilename(
        filetypes=[("Text files", "*.txt*"), ("All files", "*.*")]
    )
    encryptfilename.insert(0, filename)

def Decrypt_browse_key():
    """Open a file dialog to select a file for decryption with a secret key."""
    decryptfilename.delete(0, ctk.END)
    filename = ctk.filedialog.askopenfilename(
        filetypes=[("Encrypted files", "*.encrypted*")]
    )
    decryptfilename.insert(0, filename)

def Encrypt_browse_pass():
    """Open a file dialog to select a file for encryption with a password."""
    encryptfilenamepass.delete(0, ctk.END)
    filename = ctk.filedialog.askopenfilename(
        filetypes=[("Text files", "*.txt*"), ("All files", "*.*")]
    )
    encryptfilenamepass.insert(0, filename)

def Decrypt_browse_pass():
    """Open a file dialog to select a file for decryption with a password."""
    decryptfilenamepass.delete(0, ctk.END)
    filename = ctk.filedialog.askopenfilename(
        filetypes=[("Encrypted files", "*.encrypted*")]
    )
    decryptfilenamepass.insert(0, filename)

# Encryption/Decryption functions
def Encrypt_with_SecretKey():
    """
    Calls the encrypt_file function to encrypt the selected file using a secret key.
    """
    file = encryptfilename.get()
    key = load_key()  # Load the secret key
    try:
        encrypt_file(file, key)
        msg.showinfo("Success", f"File '{file}' encrypted successfully.")
    except Exception as e:
        msg.showerror("Error", f"Encryption failed: {str(e)}")

def Decrypt_with_SecretKey():
    """
    Calls the decrypt_file function to decrypt the selected file using a secret key.
    """
    file = decryptfilename.get()
    key = load_key()  # Load the secret key
    try:
        decrypt_file(file, key)
        msg.showinfo("Success", f"File '{file}' decrypted successfully.")
    except Exception as e:
        msg.showerror("Error", f"Decryption failed: {str(e)}")

def Encrypt_with_Password():
    """
    Calls the encrypt_file function to encrypt the selected file using a password.
    Prompts for password confirmation to ensure no mismatches.
    """
    file = encryptfilenamepass.get()

    # Ask the user to enter the password
    password = simpledialog.askstring("Password", "Enter password for encryption", show="*")
    
    if password:
        # Ask for password confirmation
        confirm_password = simpledialog.askstring("Password", "Confirm password", show="*")

        # Check if the passwords match
        if password != confirm_password:
            msg.showerror("Error", "Passwords do not match. Please try again.")
            return  # Exit the function early if passwords don't match

        # If passwords match, proceed with encryption
        key, salt = get_key_from_password(password)
        try:
            encrypt_file(file, key)
            msg.showinfo("Success", f"File '{file}' encrypted successfully.")
        except Exception as e:
            msg.showerror("Error", f"Encryption failed: {str(e)}")

def Decrypt_with_Password():
    """
    Calls the decrypt_file function to decrypt the selected file using a password.
    """
    file = decryptfilenamepass.get()
    password = simpledialog.askstring("Password", "Enter password for decryption", show="*")
    if password:
        salt = retrieve_salt_from_file(file)
        key, _ = get_key_from_password(password, salt)
        try:
            decrypt_file(file, key)
            msg.showinfo("Success", f"File '{file}' decrypted successfully.")
        except Exception as e:
            msg.showerror("Error", f"Decryption failed: {str(e)}")

# GUI Layout for Encryption and Decryption using Secret Key

key_frame = ctk.CTkFrame(app)
key_frame.pack(anchor=ctk.N, fill=ctk.X)

# Encrypt Section (Secret Key)
encryptfileLabel = ctk.CTkLabel(key_frame, text="Encrypt File", font=("Helvetica", 15))
encryptfileLabel.pack(anchor=ctk.NW, padx=(20, 0), pady=(5, 0))

encrypt_frame = ctk.CTkFrame(key_frame)
encrypt_frame.pack(anchor=ctk.NW, padx=20)

encryptfilename = ctk.CTkEntry(encrypt_frame, width=450, font=("Helvetica", 15))
encryptfilename.pack(side=ctk.LEFT)

encryptbrowsebutton = ctk.CTkButton(
    encrypt_frame, text="Browse", command=Encrypt_browse_key
)
encryptbrowsebutton.pack(side=ctk.LEFT)

encryptwithkey = ctk.CTkButton(
    key_frame, text="Encrypt", command=Encrypt_with_SecretKey
)
encryptwithkey.pack(anchor=ctk.W, padx=20)

# Decrypt Section (Secret Key)
decryptfileLabel = ctk.CTkLabel(key_frame, text="Decrypt File", font=("Helvetica", 15))
decryptfileLabel.pack(anchor=ctk.NW, padx=(20, 0), pady=(5, 0))

decrypt_frame = ctk.CTkFrame(key_frame)
decrypt_frame.pack(anchor=ctk.NW, padx=20)

decryptfilename = ctk.CTkEntry(decrypt_frame, width=450, font=("Helvetica", 15))
decryptfilename.pack(side=ctk.LEFT)

decryptbrowsebutton = ctk.CTkButton(
    decrypt_frame, text="Browse", command=Decrypt_browse_key
)
decryptbrowsebutton.pack(side=ctk.LEFT)

decryptwithkey = ctk.CTkButton(
    key_frame, text="Decrypt", command=Decrypt_with_SecretKey
)
decryptwithkey.pack(anchor=ctk.W, padx=20)

# GUI Layout for Encryption and Decryption using Password

password_frame = ctk.CTkFrame(app)
password_frame.pack(anchor=ctk.N, fill=ctk.X)

# Encrypt Section (Password)
encryptfileLabelpass = ctk.CTkLabel(
    password_frame, text="Encrypt File (Password)", font=("Helvetica", 15)
)
encryptfileLabelpass.pack(anchor=ctk.NW, padx=(20, 0), pady=(5, 0))

encrypt_framepass = ctk.CTkFrame(password_frame)
encrypt_framepass.pack(anchor=ctk.NW, padx=20)

encryptfilenamepass = ctk.CTkEntry(encrypt_framepass, width=450, font=("Helvetica", 15))
encryptfilenamepass.pack(side=ctk.LEFT)

encryptbrowsebuttonpass = ctk.CTkButton(
    encrypt_framepass, text="Browse", command=Encrypt_browse_pass
)
encryptbrowsebuttonpass.pack(side=ctk.LEFT)

encryptwithkeypass = ctk.CTkButton(
    password_frame, text="Encrypt with Password", command=Encrypt_with_Password
)
encryptwithkeypass.pack(anchor=ctk.W, padx=20)

# Decrypt Section (Password)
decryptfileLabelpass = ctk.CTkLabel(
    password_frame, text="Decrypt File", font=("Helvetica", 15)
)
decryptfileLabelpass.pack(anchor=ctk.NW, padx=(20, 0), pady=(5, 0))

decrypt_framepass = ctk.CTkFrame(password_frame)
decrypt_framepass.pack(anchor=ctk.NW, padx=20)

decryptfilenamepass = ctk.CTkEntry(decrypt_framepass, width=450, font=("Helvetica", 15))
decryptfilenamepass.pack(side=ctk.LEFT)

decryptbrowsebuttonpass = ctk.CTkButton(
    decrypt_framepass, text="Browse", command=Decrypt_browse_pass
)
decryptbrowsebuttonpass.pack(side=ctk.LEFT)

decryptwithkeypass = ctk.CTkButton(
    password_frame, text="Decrypt with Password", command=Decrypt_with_Password
)
decryptwithkeypass.pack(anchor=ctk.W, padx=20)

# Start the app's main event loop
app.mainloop()

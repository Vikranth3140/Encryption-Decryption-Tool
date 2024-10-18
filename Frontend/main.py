import customtkinter as ctk
import script
app = ctk.CTk()

def CenterWindowToDisplay(Screen: ctk, width: int, height: int, scale_factor: float = 1.0):
    """Centers the window to the main display/monitor"""
    screen_width = Screen.winfo_screenwidth()
    screen_height = Screen.winfo_screenheight()
    x = int(((screen_width/2) - (width/2)) * scale_factor)
    y = int(((screen_height/2) - (height/1.5)) * scale_factor)
    return f"{width}x{height}+{x}+{y}"

app.geometry(CenterWindowToDisplay(app, 650, 400, app._get_window_scaling()))
app.title('Encryption and Decryption')

heading_frame = ctk.CTkFrame(app)
heading_frame.pack(anchor=ctk.N, fill=ctk.X)

heading_label = ctk.CTkLabel(heading_frame, text="Encryption and Decryption", font=("Helvetica", 30))
heading_label.pack(anchor=ctk.CENTER, fill=ctk.X)

def Ebrowsekey():

    filename = ctk.filedialog.askopenfilename(filetypes=[("Encryption", "*.txt*"), ("Decryption", "*.decrypted*")])
    encryptfilename.insert(0, filename)
def Dbrowsekey():

    filename = ctk.filedialog.askopenfilename(filetypes=[("Decryption", "*.encrypted*")])
    decryptfilename.insert(0, filename)
def Ebrowsepass():

    filename = ctk.filedialog.askopenfilename(filetypes=[("Encryption", "*.txt*"), ("Decryption", "*.decrypted*")])
    encryptfilenamepass.insert(0, filename)
def Dbrowsepass():

    filename = ctk.filedialog.askopenfilename(filetypes=[("Decryption", "*.encrypted*")])
    decryptfilenamepass.insert(0, filename)

def EwithSecretKey():
    file = encryptfilename.get()
    script.encrypt_file(file, 'key', 0)


def DwithSecretKey():
    file = decryptfilename.get()
    script.decrypt_file(file, 'key', 0)


def EwithPassword():
    file = encryptfilenamepass.get()
    script.encrypt_file(file, 'password', 0)

def DwithPassword():
    file = decryptfilenamepass.get()
    script.decrypt_file(file, 'password', 0)

# using Key

key_frame = ctk.CTkFrame(app)
key_frame.pack(anchor=ctk.N, fill=ctk.X)

encryptfileLabel = ctk.CTkLabel(key_frame, text="Encrypt File", font=("Helvetica", 15))
encryptfileLabel.pack(anchor=ctk.NW, padx=(20, 0), pady=(5, 0))

encrypt_frame = ctk.CTkFrame(key_frame)
encrypt_frame.pack(anchor=ctk.NW, padx=20)

# Add the entry and button to the new frame
encryptfilename = ctk.CTkEntry(encrypt_frame, width=450, font=("Helvetica", 15))
encryptfilename.pack(side=ctk.LEFT)

encryptbrowsebutton = ctk.CTkButton(encrypt_frame, text='Browse', command=Ebrowsekey)
encryptbrowsebutton.pack(side=ctk.LEFT)

encryptwithkey = ctk.CTkButton(key_frame, text='Encrypt', command=EwithSecretKey)
encryptwithkey.pack(anchor=ctk.W, padx=20)

decryptfileLabel = ctk.CTkLabel(key_frame, text="Decrypt File", font=("Helvetica", 15))
decryptfileLabel.pack(anchor=ctk.NW, padx=(20,0), pady=(5,0))

decrypt_frame = ctk.CTkFrame(key_frame)
decrypt_frame.pack(anchor=ctk.NW, padx=20)

decryptfilename = ctk.CTkEntry(decrypt_frame, width=450, font=("Helvetica", 15))
decryptfilename.pack(side=ctk.LEFT)

decryptbrowsebutton = ctk.CTkButton(decrypt_frame, text='Browse', command=Dbrowsekey)
decryptbrowsebutton.pack(side=ctk.LEFT)

decryptwithkey = ctk.CTkButton(key_frame, text='Decrypt', command=DwithSecretKey)
decryptwithkey.pack(anchor=ctk.W, padx=20)

# Using Password


password_frame = ctk.CTkFrame(app)
password_frame.pack(anchor=ctk.N, fill=ctk.X)

encryptfileLabelpass = ctk.CTkLabel(password_frame, text="Encrypt File (Password)", font=("Helvetica", 15))
encryptfileLabelpass.pack(anchor=ctk.NW, padx=(20, 0), pady=(5, 0))

encrypt_framepass = ctk.CTkFrame(password_frame)
encrypt_framepass.pack(anchor=ctk.NW, padx=20)

# Add the entry and button to the new frame
encryptfilenamepass = ctk.CTkEntry(encrypt_framepass, width=450, font=("Helvetica", 15))
encryptfilenamepass.pack(side=ctk.LEFT)

encryptbrowsebuttonpass = ctk.CTkButton(encrypt_framepass, text='Browse', command=Ebrowsepass)
encryptbrowsebuttonpass.pack(side=ctk.LEFT)

encryptwithkeypass = ctk.CTkButton(password_frame, text='Encrypt with Password', command=EwithPassword)
encryptwithkeypass.pack(anchor=ctk.W, padx=20)

decryptfileLabelpass = ctk.CTkLabel(password_frame, text="Decrypt File", font=("Helvetica", 15))
decryptfileLabelpass.pack(anchor=ctk.NW, padx=(20,0), pady=(5,0))

decrypt_framepass = ctk.CTkFrame(password_frame)
decrypt_framepass.pack(anchor=ctk.NW, padx=20)

decryptfilenamepass = ctk.CTkEntry(decrypt_framepass, width=450, font=("Helvetica", 15))
decryptfilenamepass.pack(side=ctk.LEFT)

decryptbrowsebuttonpass = ctk.CTkButton(decrypt_framepass, text='Browse', command=Dbrowsepass)
decryptbrowsebuttonpass.pack(side=ctk.LEFT)

decryptwithkeypass = ctk.CTkButton(password_frame, text='Decrypt with Password', command=DwithPassword)
decryptwithkeypass.pack(anchor=ctk.W, padx=20)


app.mainloop()

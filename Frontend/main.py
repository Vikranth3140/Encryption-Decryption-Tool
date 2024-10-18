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

key_frame = ctk.CTkFrame(app)
key_frame.pack(anchor=ctk.N, fill=ctk.X)

def Ebrowse():

    filename = ctk.filedialog.askopenfilename(filetypes=[("Encryption", "*.txt*"), ("Decryption", "*.decrypted*")])
    encryptfilename.insert(0, filename)
def Dbrowse():

    filename = ctk.filedialog.askopenfilename(filetypes=[("Decryption", "*.encrypted*")])
    decryptfilename.insert(0, filename)

def EwithSecretKey():
    file = encryptfilename.get()
    script.encrypt_file(file, 'key')


def DwithSecretKey():
    file = encryptfilename.get()
    script.decrypt_file(file, 'key')


def EwithPassword():
    pass

def DwithPassword():
    pass

encryptfileLabel = ctk.CTkLabel(key_frame, text="Encrypt File", font=("Helvetica", 15))
encryptfileLabel.pack(anchor=ctk.NW, padx=(20, 0), pady=(5, 0))

encrypt_frame = ctk.CTkFrame(key_frame)
encrypt_frame.pack(anchor=ctk.NW, padx=20)

# Add the entry and button to the new frame
encryptfilename = ctk.CTkEntry(encrypt_frame, width=450, font=("Helvetica", 15))
encryptfilename.pack(side=ctk.LEFT)

encryptbrowsebutton = ctk.CTkButton(encrypt_frame, text='Browse', command=Ebrowse)
encryptbrowsebutton.pack(side=ctk.LEFT)

encryptwithkey = ctk.CTkButton(key_frame, text='Encrypt', command=EwithSecretKey)
encryptwithkey.pack(anchor=ctk.W, padx=20)

decryptfileLabel = ctk.CTkLabel(key_frame, text="Decrypt File", font=("Helvetica", 15))
decryptfileLabel.pack(anchor=ctk.NW, padx=(20,0), pady=(5,0))

decrypt_frame = ctk.CTkFrame(key_frame)
decrypt_frame.pack(anchor=ctk.NW, padx=20)

decryptfilename = ctk.CTkEntry(decrypt_frame, width=450, font=("Helvetica", 15))
decryptfilename.pack(side=ctk.LEFT)

decryptbrowsebutton = ctk.CTkButton(decrypt_frame, text='Browse', command=Dbrowse)
decryptbrowsebutton.pack(side=ctk.LEFT)

decryptwithkey = ctk.CTkButton(key_frame, text='Decrypt', command=DwithSecretKey)
decryptwithkey.pack(anchor=ctk.W, padx=20)


app.mainloop()

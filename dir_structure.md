```
ENCRYPTION-PROJECT/
│
├── encryption_decryption_tool/
│   ├── __init__.py           # Makes the folder a package
│   ├── encryption.py         # Contains encryption logic from script.py
│   ├── decryption.py         # Contains decryption logic from script.py
│
├── Frontend/
│   └── main.py               # Main file for the frontend logic (can be improved later)
├── tests/
│   ├── test_encryption.py    # Unit tests for encryption functionality
│   ├── test_decryption.py    # Unit tests for decryption functionality
│
├── .gitignore                # Git configuration to ignore unnecessary files
├── LICENSE                   # License information
├── LINK.md                   # External links related to the project
├── README.md                 # Project documentation
├── requirements.txt          # Python dependencies
├── sample.txt                # Sample text file for testing encryption
├── sample.txt.decrypted       # Decrypted version of the sample text
├── sample.txt.encrypted       # Encrypted version of the sample text
├── setup.py                  # The setup file for packaging
└── secret.key                # Secret key file used for encryption/decryption
```
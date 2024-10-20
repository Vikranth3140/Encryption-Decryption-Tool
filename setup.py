from setuptools import setup, find_packages

setup(
    name='encryption_decryption_tool',
    version='0.1',
    description='A tool for encrypting and decrypting files',
    author='Vikranth Udandarao',
    author_email='vikranth22570@iiitd.ac.in',
    url='https://github.com/Vikranth3140/Encryption-Decryption-Tool',
    packages=find_packages(),
    install_requires=[
        'cryptography',
        'customtkinter'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)

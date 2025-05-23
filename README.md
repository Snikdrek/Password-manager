﻿# Password-manager
A lightweight command-line password manager built with Python and cryptography.
This tool encrypts and securely stores your account passwords using a master password and salt-based key derivation (PBKDF2HMAC).
All data is locally stored and protected using symmetric encryption (Fernet).

✨ Features:
Master password-based encryption

Secure key derivation using PBKDF2 + SHA-256

Local storage of encrypted credentials

Add and view account passwords

Auto-generates and stores a salt for secure key generation

⚠️ Note:
If the master password is forgotten, encrypted data cannot be recovered.

import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_FILE = "salt.key"
PASSWORDS_FILE = "passwords.txt"

def get_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    return salt

# Prompt user for the master password
pwd = input("What is the master password? ").encode()

# Load or generate salt
salt = get_salt()

# Derive key
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=1_200_000,
)
key = base64.urlsafe_b64encode(kdf.derive(pwd))
fer = Fernet(key)

# View saved passwords
def view():
    try:
        with open(PASSWORDS_FILE, 'r') as f:
            for line in f.readlines():
                user, encrypted_psw = line.strip().split("|")
                decrypted_psw = fer.decrypt(encrypted_psw.encode()).decode()
                print(f"User: {user}, Pass: {decrypted_psw}")
    except FileNotFoundError:
        print("No passwords stored yet!")
    except Exception as e:
        print("Error:", e)

# Add a new password
def add():
    name = input("Account name: ")
    pas = input("Password: ")
    with open(PASSWORDS_FILE, 'a') as f:
        f.write(name + "|" + fer.encrypt(pas.encode()).decode() + "\n")

# Main loop
while True:
    mode = input("Would you like to add a new password or view existing ones? (add/view/quit): ").strip().lower()
    
    if mode == 'quit':
        break
    elif mode == 'view':
        view()
    elif mode == 'add':
        add()
    else:
        print("Invalid option!")

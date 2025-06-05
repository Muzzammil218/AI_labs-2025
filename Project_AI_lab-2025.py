import os, json, base64, getpass, hashlib
from cryptography.fernet import Fernet
import pyfiglet
import re
import base64
import getpass
import hashlib

MASTER_FILE = 'master.json'
DATA_FILE = 'vault.json'

# ----------------- Helper Functions -----------------

def welcome():
    print(pyfiglet.figlet_format('SecureVault', font='slant'))

def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.b64encode(salt + key).decode()

def verify_password(stored, provided):
    decoded = base64.b64decode(stored)
    salt, key = decoded[:16], decoded[16:]
    test_key = hashlib.pbkdf2_hmac('sha256', provided.encode(), salt, 100000)
    return key == test_key

def generate_key(password):
    salt = b"static_salt_here"  # For Fernet key, must be same every time
    kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(kdf[:32])

# ----------------- Input Validation -----------------

def input_website():
    website = input("Enter the website: ")
    if re.search(r"^(https?://)?(www\.)?([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$", website):
        return website
    print("NOt true")
    return None

def input_username():
    username = input("Enter your username: ")
    if re.search(r"^[a-zA-Z0-9_.-]+$", username):
        return username
    print("Not true")
    return None

def input_password():
    password = input("Enter your password: ")
    if re.search(r"^\S{5,}$", password):
        return password
    print("Not true")
    return None

# ----------------- Vault Functions -----------------

def setup_master_password():
    print("🔒 Set a master password for your vault.")
    while True:
        pw1 = getpass.getpass("Create master password: ")
        pw2 = getpass.getpass("Confirm master password: ")
        if pw1 == pw2 and len(pw1) >= 5:
            hashed = hash_password(pw1)
            with open(MASTER_FILE, 'w') as f:
                json.dump({'hash': hashed}, f)
            print("✅ Master password set.")
            return pw1
        else:
            print("❌ Passwords did not match or were too short. Try again.")

def login():
    if not os.path.exists(MASTER_FILE):
        return setup_master_password()
    with open(MASTER_FILE) as f:
        master_data = json.load(f)
    for _ in range(3):
        pw = getpass.getpass("Enter master password: ")
        if verify_password(master_data['hash'], pw):
            print("✅ Access granted.")
            return pw
        else:
            print("❌ Incorrect password.")
    print("Too many failed attempts. Exiting.")
    exit()

def load_vault():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def save_vault(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def add_password(vault, fernet):
    website = input_website()
    username = input_username()
    password = input_password()
    if not (website and username and password):
        print("❌ Invalid input. Try again.")
        return
    encrypted_pw = fernet.encrypt(password.encode()).decode()
    vault.append({
        'Website': website,
        'Username': username,
        'Password': encrypted_pw
    })
    save_vault(vault)
    print("✅ Password saved securely.")

def view_passwords(vault, fernet):
    if not vault:
        print("🔐 No saved passwords.")
        return
    print("\nSaved Passwords:")
    for entry in vault:
        try:
            decrypted_pw = fernet.decrypt(entry['Password'].encode()).decode()
            print(f"🔹 {entry['Website']} | {entry['Username']} | {decrypted_pw}")
        except:
            print(f"❌ Failed to decrypt password for {entry['Website']}")

# ----------------- Main App -----------------

def main():
    welcome()
    master_password = login()
    fernet = Fernet(generate_key(master_password))
    vault = load_vault()

    while True:
        print("\nWhat do you want to do?")
        print("1. Add a new password")
        print("2. View saved passwords")
        print("3. Quit")

        choice = input("Enter choice (1/2/3): ").strip()
        if choice == '1':
            add_password(vault, fernet)
        elif choice == '2':
            view_passwords(vault, fernet)
        elif choice == '3':
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid option. Try again.")

if __name__ == "__main__":
    main()

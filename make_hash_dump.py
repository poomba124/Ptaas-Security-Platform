# make_hash_dump.py (Updated for BNY)
import bcrypt
import json
import hashlib
import os
from argon2 import PasswordHasher

# --- NEW ADDITION ---
COMPANY_PEPPER = b"BNY" # Define the company name as a bytes object
# --------------------

# Initialize Argon2
ph = PasswordHasher()

# A single list of users and their passwords
users = {
    # Simple Dictionary Hits
    "alice": b"password",
    "bob": b"123456",
    "charlie": b"qwerty",
    "diana": b"football",
    "edward": b"welcome",
    "fiona": b"dragon",

    # Rule-Based Hits (Capitalization, Suffixes, Leetspeak from wordlist)
    "george": b"Password123", # From 'password'
    "hannah": b"Welcome!",    # From 'welcome'
    "ian": b"Qwerty1234",  # From 'qwerty'
    "julia": b"dr@gon",      # From 'dragon' (leetspeak 'a')
    "kevin": b"f00tball",    # From 'football' (leetspeak 'o')
    "laura": b"Sun$hine",    # From 'sunshine' (leetspeak 's' + capitalization)

    # Keyboard Pattern (Will only be classified if cracked)
    "mike": b"asdfgh",

    # More Complex / Potentially Uncrackable by basic rules/list
    "nancy": b"MyP@sswOrd!2024",
    "oliver": b"Sup3rS3cur3!",
    "penny": b"Manipal!@#", # Example using location context
    "quentin": b"P@$$wOrdRuLe$",

    # Common Variations
    "rita": b"password!",
    "steve": b"admin123",
    "tina": b"secret1",
    "umar": b"india123", # Example using location context
    "violet": b"123456!",
    "walter": b"welcome1"
}

out = {}
print(f"Generating 5 hashes for each user using company pepper: {COMPANY_PEPPER.decode()}...")

# Loop through each user and create all five hash entries
for username, pw in users.items():
    
    # 1. MD5 (legacy, insecure) - PEPPERED
    # We combine the password and the company name before hashing.
    peppered_pw = pw 
    out[f"{username}_md5_bny"] = hashlib.md5(peppered_pw).hexdigest()

    # 2. SHA-256 (fast, unsalted) - PEPPERED
    # We combine the password and the company name before hashing.
    peppered_pw = pw 
    out[f"{username}_sha256_bny"] = hashlib.sha256(peppered_pw).hexdigest()
    
    # 3. PBKDF2 (standard KDF) - Uses its own strong random salt
    salt = os.urandom(16)
    pbkdf2_hash = hashlib.pbkdf2_hmac('sha256', pw, salt, 100000)
    out[f"{username}_pbkdf2"] = f"pbkdf2${salt.hex()}${pbkdf2_hash.hex()}"
    
    # 4. bcrypt (standard KDF) - Uses its own strong random salt
    out[f"{username}_bcrypt"] = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode()
    
    # 5. Argon2 (modern KDF) - Uses its own strong random salt
    out[f"{username}_argon2"] = ph.hash(pw)

with open("bny_user_hashes.json", "w") as f:
    json.dump(out, f, indent=2)

print(f"Wrote bny_user_hashes.json with 5 parallel hashes for each user.")
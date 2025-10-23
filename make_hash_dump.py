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
# In make_hash_dump.py

# Comprehensive list for testing all features with company name "Lenovo"
users = {
    # --- For Dictionary + Rules Attack ---
    "dict_user1": b"password",          # Direct hit from wordlist
    "dict_user2": b"Lenovo",            # Direct hit (if base word in list) + Capitalize rule
    "dict_user3": b"sunshine123",       # Base word + Suffix rule
    "dict_user4": b"Welcome!",          # Base word + Capitalize + Suffix rule
    "dict_user5": b"dr@gon",            # Base word + Leetspeak rule
    "dict_user6": b"Adm1n",             # Base word 'admin' + Capitalize + Leetspeak 'i'
    "dict_user7": b"PASSWORD",          # Base word + Uppercase rule
    "dict_user8": b"123baseball",       # Base word + Prefix rule

    # --- For "AI" / Advanced Rule Attack (Seed: "Lenovo") ---
    "ai_user1": b"lenovo",              # Basic variation
    "ai_user2": b"LENOVO!",             # Basic variation + Suffix
    "ai_user3": b"L3n0v0",              # Leetspeak variation
    "ai_user4": b"Lenovo2024",          # Seed + Year variation
    "ai_user5": b"adminLenovo",         # Common word combination
    "ai_user6": b"LenovoSecure123",     # Seed + Common word + Suffix (tests combination rule)
    "ai_user7": b"#LENOVO",             # Symbol prefix variation

    # --- For Mask Attack ---
    "mask_user1": b"Pass12",            # Example for mask: ?u?l?l?d?d
    "mask_user2": b"Qaz!99",            # Example for mask: ?u?l?l?s?d?d
    "mask_user3": b"hello$",            # Example for mask: ?l?l?l?l?l?s

    # --- For Analysis (Keyboard Patterns, Predictable) ---
    "analysis_user1": b"qwerty789",     # Keyboard pattern + Sequential
    "analysis_user2": b"asdfg!",        # Keyboard pattern + Symbol
    "analysis_user3": b"12345abc",      # Sequential

    # --- More Complex / Harder to Crack ---
    "complex_user1": b"L3n0v0Rul3$!",    # AI seed + Leet + Word + Suffix + Symbol
    "complex_user2": b"MyN3wP@ss!",      # Not easily guessable by current rules/AI
    "complex_user3": b"WelcomeToManipal25", # Requires word combination + Location + Year

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
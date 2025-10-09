# make_hash_dump.py (Updated for 5 algorithms)
import bcrypt
import json
import hashlib
import os
from argon2 import PasswordHasher

# Initialize Argon2
ph = PasswordHasher()

# A single list of users and their passwords
users = {
    "alice": b"password"
}

out = {}
print("Generating 5 hashes for each user (MD5, SHA256, PBKDF2, bcrypt, Argon2)...")

# Loop through each user and create all five hash entries
for username, pw in users.items():
    # 1. MD5 (legacy, insecure)
    out[f"{username}_md5"] = hashlib.md5(pw).hexdigest()

    # 2. SHA-256 (fast, unsalted)
    out[f"{username}_sha256"] = hashlib.sha256(pw).hexdigest()
    
    # 3. PBKDF2 (standard KDF)
    salt = os.urandom(16)
    pbkdf2_hash = hashlib.pbkdf2_hmac('sha256', pw, salt, 100000)
    # Store as algorithm$salt$hash for easy verification
    out[f"{username}_pbkdf2"] = f"pbkdf2${salt.hex()}${pbkdf2_hash.hex()}"
    
    # 4. bcrypt (standard KDF)
    out[f"{username}_bcrypt"] = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode()
    
    # 5. Argon2 (modern KDF)
    out[f"{username}_argon2"] = ph.hash(pw)

with open("user_hashes.json", "w") as f:
    json.dump(out, f, indent=2)

print("Wrote user_hashes.json with 5 parallel hashes for each user.")
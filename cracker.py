# cracker.py (Updated with Rule-Based Attacks)
import argparse
import json
import threading
import queue
import hashlib
import bcrypt
import time
import os
import itertools
import string
from typing import Dict
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import re
from collections import Counter

ph = PasswordHasher()

# --- NEW: Rule Generation Function ---
def apply_rules(word: str):
    """
    Applies a more comprehensive set of common password mangling rules.
    """
    # 1. Case Variations
    yield word.lower()
    yield word.upper()
    if word:
        yield word.capitalize()

    # 2. Simple Leetspeak Substitutions (This will find 'passw0rd')
    # It tries replacing one character at a time.
    substitutions = [('o', '0'), ('a', '@'), ('e', '3'), ('s', '$'), ('i', '1')]
    for char, sub in substitutions:
        if char in word:
            # Replace only the first instance of the character
            yield word.replace(char, sub, 1)
            # You could also add a rule to replace all instances
            # yield word.replace(char, sub)

    # 3. Common Appending and Prepending
    suffixes = ["1", "123", "!", "2024", "2025"]
    prefixes = ["!", "123"]

    for suffix in suffixes:
        yield word + suffix
        if word:
            yield word.capitalize() + suffix
    
    for prefix in prefixes:
        yield prefix + word

    # 4. Combination Rule Example (Capitalize + Suffix)
    if word:
        yield word.capitalize() + "!"

def detect_hash_type(hash_str: str):
    # This function remains unchanged
    if hash_str.startswith("$2"):
        return "bcrypt"
    if hash_str.startswith("$argon2"):
        return "argon2"
    if hash_str.startswith("pbkdf2$"):
        return "pbkdf2"
    s = hash_str.strip()
    if all(c in "0123456789abcdefABCDEF" for c in s):
        if len(s) == 32:
            return "md5"
        if len(s) == 40:
            return "sha1"
        if len(s) == 64:
            return "sha256"
    return "unknown"

def verify_candidate(candidate: str, hash_str: str, htype: str) -> bool:
    # This function remains unchanged
    pw_bytes = candidate.encode("utf-8")
    if htype == "bcrypt":
        try:
            return bcrypt.checkpw(pw_bytes, hash_str.encode("utf-8"))
        except Exception:
            return False
    elif htype == "argon2":
        try:
            ph.verify(hash_str, pw_bytes)
            return True
        except VerifyMismatchError:
            return False
    elif htype == "pbkdf2":
        try:
            _, salt_hex, hash_hex = hash_str.split('$')
            salt = bytes.fromhex(salt_hex)
            stored_hash = bytes.fromhex(hash_hex)
            new_hash = hashlib.pbkdf2_hmac('sha256', pw_bytes, salt, 100000)
            return new_hash == stored_hash
        except Exception:
            return False
    elif htype == "md5":
        return hashlib.md5(pw_bytes).hexdigest() == hash_str.lower()
    elif htype == "sha256":
        return hashlib.sha256(pw_bytes).hexdigest() == hash_str.lower()
    else:
        return False
    
def analyze_passwords(cracked_passwords: list, company_name: str = None):
    """Analyzes a list of cracked passwords for common weaknesses."""
    analysis = {
        "common_patterns": {
            "contains_company_name_percent": 0.0,
            "ends_with_year_percent": 0.0,
            "is_all_lowercase_percent": 0.0
        },
        "recommendations": [
            "Enforce Multi-Factor Authentication (MFA) for all users to mitigate the risk from compromised passwords.",
            "Increase the minimum password length requirement to at least 12 characters.",
            "Implement a breached password filter to prevent users from choosing passwords known to be compromised.",
            "Use these anonymous statistics to conduct security awareness training for all employees."
        ]
    }
    
    if not cracked_passwords:
        return analysis

    count = len(cracked_passwords)
    company_name_count = 0
    ends_with_year_count = 0
    all_lowercase_count = 0

    for item in cracked_passwords:
        pw = item['password']
        
        # Check for company name (if provided)
        if company_name and company_name.lower() in pw.lower():
            company_name_count += 1
        
        # Check if password ends in a 4-digit number (like a year)
        if re.search(r'\d{4}$', pw):
            ends_with_year_count += 1
            
        # Check if the password is all lowercase
        if pw.islower():
            all_lowercase_count += 1
            
    analysis["common_patterns"]["contains_company_name_percent"] = round((company_name_count / count) * 100, 2)
    analysis["common_patterns"]["ends_with_year_percent"] = round((ends_with_year_count / count) * 100, 2)
    analysis["common_patterns"]["is_all_lowercase_percent"] = round((all_lowercase_count / count) * 100, 2)
    
    return analysis

def mask_generator(mask: str):
    """
    Generates all possible candidates for a given mask.
    ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special
    """
    charsets = {
        '?l': string.ascii_lowercase,
        '?u': string.ascii_uppercase,
        '?d': string.digits,
        '?s': string.punctuation
    }

    # --- THIS IS THE CORRECTED LOGIC ---
    # Instead of splitting, we loop through the mask two characters at a time.
    groups = []
    i = 0
    while i < len(mask):
        token = mask[i:i+2] # Read two characters, e.g., "?u"
        if token in charsets:
            groups.append(charsets[token])
            i += 2 # Move to the next token
        else:
            # Handle an invalid token
            print(f"Error: Invalid mask token '{token}' found. Please use ?l, ?u, ?d, or ?s.")
            return
    # --- END CORRECTION ---

    # The rest of the function works as before
    for combo in itertools.product(*groups):
        yield ''.join(combo)

def worker(job_q: queue.Queue, results_q: queue.Queue, user_hashes: Dict[str,str],
           user_types: Dict[str,str], found: Dict[str,str], found_lock: threading.Lock,
           stop_event: threading.Event, wid: int):
    # This function remains unchanged
    while not stop_event.is_set():
        try:
            candidate = job_q.get(timeout=0.5)
        except queue.Empty:
            continue
        for user, hash_str in user_hashes.items():
            with found_lock:
                if user in found:
                    continue
            htype = user_types[user]
            try:
                if verify_candidate(candidate, hash_str, htype):
                    with found_lock:
                        if user not in found:
                            found[user] = candidate
                            results_q.put((user, candidate, htype, wid))
            except NotImplementedError:
                pass
        job_q.task_done()

# In cracker.py

def main():
    # --- This part for argparse remains the same ---
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash-file", required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--mode", required=True, choices=['dictionary', 'mask'])
    parser.add_argument("--wordlist", help="Path for dictionary mode")
    parser.add_argument("--mask", help="Mask pattern for mask mode")
    parser.add_argument("--company-name", help="Company name to check for in passwords.")
    args = parser.parse_args()

    # --- Argument validation remains the same ---
    if args.mode == 'dictionary' and not args.wordlist:
        print(json.dumps({"error": "--wordlist is required for dictionary mode."}))
        return
    if args.mode == 'mask' and not args.mask:
        print(json.dumps({"error": "--mask is required for mask mode."}))
        return
    # ... (other file checks) ...

    with open(args.hash_file, "r") as f:
        user_hashes = json.load(f)

    # --- NEW: Initialize the report_data dictionary (This is the fix) ---
    report_data = {
        "summary": {
            "total_hashes": len(user_hashes),
            "cracked_count": 0,
            "crack_rate_percent": 0.0,
            "duration_seconds": 0.0
        },
        "performance_benchmark": {},
        "cracked_passwords": [],
        "top_passwords": [],
        "analysis": {} # Placeholder for the analysis results
    }

    # --- The setup for workers and queues remains the same ---
    user_types = {}
    total_hashes_by_type = {}
    for user, h in user_hashes.items():
        t = detect_hash_type(h)
        user_types[user] = t
        total_hashes_by_type.setdefault(t, 0)
        total_hashes_by_type[t] += 1
    
    job_q = queue.Queue(maxsize=20000)
    results_q = queue.Queue()
    stop_event = threading.Event()
    found = {}
    found_lock = threading.Lock()
    timing_data = {htype: {'found_count': 0, 'end_time': None} for htype in total_hashes_by_type}
    
    workers_list = []
    for i in range(args.workers):
        t = threading.Thread(target=worker, args=(job_q, results_q, user_hashes, user_types, found, found_lock, stop_event, i+1))
        t.daemon = True
        t.start()
        workers_list.append(t)

    # --- The producer logic remains the same ---
    producer_thread = None
    if args.mode == 'dictionary':
        def dict_producer():
            # ... (your existing dict_producer code) ...
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as wl:
                for line in wl:
                    if stop_event.is_set(): break
                    word = line.strip()
                    if word:
                        for candidate in apply_rules(word):
                            job_q.put(candidate)
        producer_thread = threading.Thread(target=dict_producer)
    elif args.mode == 'mask':
        def mask_producer():
            # ... (your existing mask_producer code) ...
            for candidate in mask_generator(args.mask):
                if stop_event.is_set(): break
                job_q.put(candidate)
        producer_thread = threading.Thread(target=mask_producer)
    
    if producer_thread:
        producer_thread.daemon = True
        producer_thread.start()

    start_time = time.time()
    
    # --- The result collection loop now populates the report_data dict ---
    try:
        while len(found) < len(user_hashes):
            try:
                user, cand, htype, wid = results_q.get(timeout=1.0)
            except queue.Empty:
                if not producer_thread.is_alive() and job_q.empty():
                    break
                continue
            
            # MODIFIED: Instead of printing, store the found password
            report_data["cracked_passwords"].append({
                "user": user,
                "password": cand,
                "hash_type": htype
            })
            
            if htype in timing_data:
                timing_data[htype]['found_count'] += 1
                if timing_data[htype]['found_count'] == total_hashes_by_type[htype]:
                    timing_data[htype]['end_time'] = time.time()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        duration = time.time() - start_time

        # --- MODIFIED: Finalize the report_data dictionary ---
        report_data["summary"]["duration_seconds"] = round(duration, 2)
        report_data["summary"]["cracked_count"] = len(found)
        if report_data["summary"]["total_hashes"] > 0:
            rate = (len(found) / len(user_hashes)) * 100
            report_data["summary"]["crack_rate_percent"] = round(rate, 2)

        for htype, data in timing_data.items():
            if data['end_time']:
                crack_duration = data['end_time'] - start_time
                report_data["performance_benchmark"][htype.upper()] = round(crack_duration, 4)
        
        if report_data["cracked_passwords"]:
            password_counts = Counter(item['password'] for item in report_data["cracked_passwords"])
            report_data["top_passwords"] = [{"password": p, "count": c} for p, c in password_counts.most_common(5)]

        analysis_results = analyze_passwords(report_data["cracked_passwords"], args.company_name)
        report_data["analysis"] = analysis_results

        # The final and only output of the script is now a single JSON object
        print(json.dumps(report_data, indent=4))

if __name__ == "__main__":
    main()
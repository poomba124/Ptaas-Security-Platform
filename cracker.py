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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash-file", required=True, help="JSON file with username->hash mapping")
    parser.add_argument("--workers", type=int, default=4, help="Number of worker threads")
    parser.add_argument("--output", default="found.json", help="Write found results to JSON")

    # --- NEW: Arguments for selecting the attack mode ---
    parser.add_argument("--mode", required=True, choices=['dictionary', 'mask'], help="The attack mode to use.")
    parser.add_argument("--wordlist", help="Path to wordlist file (for dictionary mode).")
    parser.add_argument("--mask", help="Mask pattern (for mask mode), e.g., ?u?l?l?d.")
    args = parser.parse_args()

    # --- NEW: Validate arguments based on the selected mode ---
    if args.mode == 'dictionary' and not args.wordlist:
        print("Error: --wordlist is required for dictionary mode.")
        return
    if args.mode == 'mask' and not args.mask:
        print("Error: --mask is required for mask mode.")
        return

    # --- File existence checks ---
    if not os.path.isfile(args.hash_file):
        print("Hash file not found:", args.hash_file)
        return
    # Only check for wordlist if in dictionary mode
    if args.mode == 'dictionary' and not os.path.isfile(args.wordlist):
        print("Wordlist not found:", args.wordlist)
        return

    with open(args.hash_file, "r") as f:
        user_hashes = json.load(f)

    # --- This setup part remains the same ---
    user_types = {}
    total_hashes_by_type = {}
    for user, h in user_hashes.items():
        t = detect_hash_type(h)
        user_types[user] = t
        total_hashes_by_type.setdefault(t, 0)
        total_hashes_by_type[t] += 1
        if t == "unknown":
            print(f"[warn] {user}: unknown hash type for '{h[:30]}...'")

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

    # --- MODIFIED: Select the producer based on the attack mode ---
    producer_thread = None
    if args.mode == 'dictionary':
        def dict_producer():
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as wl:
                for line in wl:
                    if stop_event.is_set(): break
                    word = line.strip()
                    if word:
                        for candidate in apply_rules(word):
                            job_q.put(candidate)
            print("[producer] dictionary finished")
        producer_thread = threading.Thread(target=dict_producer)

    elif args.mode == 'mask':
        def mask_producer():
            for candidate in mask_generator(args.mask):
                if stop_event.is_set(): break
                job_q.put(candidate)
            print("[producer] mask finished")
        producer_thread = threading.Thread(target=mask_producer)
    # --- END MODIFIED ---

    if producer_thread:
        producer_thread.daemon = True
        producer_thread.start()
    else:
        print("Error: No valid producer for the selected mode.")
        return

    # --- The final reporting loop remains unchanged ---
    print("Started workers:", args.workers)
    start_time = time.time()
    run_completed_naturally = False
    try:
        while len(found) < len(user_hashes):
            try:
                user, cand, htype, wid = results_q.get(timeout=1.0)
            except queue.Empty:
                if not producer_thread.is_alive() and job_q.empty():
                    run_completed_naturally = True
                    break
                continue
            print(f"[FOUND by worker {wid}] {user} -> {cand} (type={htype})")
            if htype in timing_data:
                timing_data[htype]['found_count'] += 1
                if timing_data[htype]['found_count'] == total_hashes_by_type[htype]:
                    timing_data[htype]['end_time'] = time.time()
    except KeyboardInterrupt:
        print("\nInterrupted by user; stopping...")
    finally:
        stop_event.set()
        duration = time.time() - start_time
        print("\nRun finished. Total time: {:.2f}s. Found: {}/{}".format(duration, len(found), len(user_hashes)))
        print("\n--- Performance Breakdown ---")
        for htype, data in timing_data.items():
            if data['end_time']:
                crack_duration = data['end_time'] - start_time
                print(f"Time to crack all {htype.upper()} hashes: {crack_duration:.4f} seconds ({data['found_count']}/{total_hashes_by_type[htype]} found)")
            elif data['found_count'] > 0:
                if run_completed_naturally:
                    print(f"Cracked {data['found_count']}/{total_hashes_by_type[htype]} {htype.upper()} hashes. (Run completed)")
                else:
                    print(f"Cracked {data['found_count']}/{total_hashes_by_type[htype]} {htype.upper()} hashes, but run ended before all were found.")
            else:
                print(f"No {htype.upper()} hashes were cracked.")
        with open(args.output, "w") as outf:
            json.dump(found, outf, indent=2)
        print("\nWrote found results to", args.output)

if __name__ == "__main__":
    main()
# realistic_cracker.py (Updated with 5 algorithms and benchmarking)
import argparse
import json
import threading
import queue
import hashlib
import bcrypt
import time
import os
from typing import Dict
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def detect_hash_type(hash_str: str):
    if hash_str.startswith("$2"):
        return "bcrypt"
    if hash_str.startswith("$argon2"):
        return "argon2"
    if hash_str.startswith("pbkdf2$"): # New
        return "pbkdf2"
    
    s = hash_str.strip()
    if all(c in "0123456789abcdefABCDEF" for c in s):
        if len(s) == 32: # New for MD5
            return "md5"
        if len(s) == 40:
            return "sha1"
        if len(s) == 64:
            return "sha256"
    return "unknown"

def verify_candidate(candidate: str, hash_str: str, htype: str) -> bool:
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
    elif htype == "pbkdf2": # New
        try:
            _, salt_hex, hash_hex = hash_str.split('$')
            salt = bytes.fromhex(salt_hex)
            stored_hash = bytes.fromhex(hash_hex)
            new_hash = hashlib.pbkdf2_hmac('sha256', pw_bytes, salt, 100000)
            return new_hash == stored_hash
        except Exception:
            return False
    elif htype == "md5": # New
        return hashlib.md5(pw_bytes).hexdigest() == hash_str.lower()
    elif htype == "sha256":
        return hashlib.sha256(pw_bytes).hexdigest() == hash_str.lower()
    else:
        return False

# The rest of the script (worker, main functions) remains the same as the previous version.
# No changes are needed in the main logic as it's designed to be modular.
def worker(job_q: queue.Queue, results_q: queue.Queue, user_hashes: Dict[str,str],
           user_types: Dict[str,str], found: Dict[str,str], found_lock: threading.Lock,
           stop_event: threading.Event, wid: int):
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
    parser.add_argument("--wordlist", required=True, help="Wordlist file (one candidate per line)")
    parser.add_argument("--workers", type=int, default=4, help="Number of worker threads")
    parser.add_argument("--output", default="found.json", help="Write found results to JSON")
    args = parser.parse_args()

    if not os.path.isfile(args.hash_file):
        print("Hash file not found:", args.hash_file)
        return
    if not os.path.isfile(args.wordlist):
        print("Wordlist not found:", args.wordlist)
        return

    with open(args.hash_file, "r") as f:
        user_hashes = json.load(f)

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

    def producer():
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as wl:
            for line in wl:
                if stop_event.is_set():
                    break
                cand = line.rstrip("\n\r")
                if not cand:
                    continue
                job_q.put(cand)
        print("[producer] finished")

    prod_thread = threading.Thread(target=producer)
    prod_thread.daemon = True
    prod_thread.start()

    print("Started workers:", args.workers)
    start_time = time.time()

    try:
        while len(found) < len(user_hashes):
            try:
                user, cand, htype, wid = results_q.get(timeout=1.0)
            except queue.Empty:
                if not prod_thread.is_alive() and job_q.empty():
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
                 print(f"Cracked {data['found_count']}/{total_hashes_by_type[htype]} {htype.upper()} hashes, but run ended before all were found.")
            else:
                print(f"No {htype.upper()} hashes were cracked.")

        with open(args.output, "w") as outf:
            json.dump(found, outf, indent=2)
        print("\nWrote found results to", args.output)

if __name__ == "__main__":
    main()
    
#python .\cracker.py --hash-file .\user_hashes.json --wordlist .\wordlist.txt --workers 4
# cracker.py (Final Version with AI-mode, Cracking, and Intelligence Reporting)
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
import random 
from typing import Dict
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import re
from collections import Counter

# Initialize Argon2 Password Hasher
ph = PasswordHasher()

# --- CONSTANTS AND HELPERS ---
COMMON_SUFFIXES = ['', '123', '1234', '01', '2020', '2021', '2022', '2023', '2024', '!', '!!', '#1', '@!']
COMMON_WORDS = ['admin', 'password', 'welcome', 'login', 'user', 'qwerty', 'secure', 'office', 'hq', 'dobby'] # Added 'dobby' for testing
LEET_MAP = str.maketrans({'a': '4', 'A': '4', 'o': '0', 'O': '0', 'i': '1', 'I': '1', 'e': '3', 'E': '3', 's': '5', 'S': '5', 't': '7', 'T': '7'})

# --- AI-STYLE CANDIDATE GENERATOR (RULE-BASED) ---
# (basic_variants, add_suffixes, leet_variants, insert_symbols, combine_with_common, random_mutations - REMAIN UNCHANGED)

def basic_variants(seed):
    """Return basic capitalization variants."""
    yield seed.lower()
    yield seed.capitalize()
    yield seed.upper()

def add_suffixes(names, suffixes):
    for n in names:
        for s in suffixes:
            yield f"{n}{s}"

def leet_variants(name):
    # full leet
    yield name.translate(LEET_MAP)
    # partial leet: replace some characters probabilistically
    chars = list(name)
    for i in range(len(chars)):
        if random.random() < 0.3:
            ch = chars[i]
            if ch in LEET_MAP:
                chars[i] = ch.translate(LEET_MAP)
    yield ''.join(chars)

def insert_symbols(name):
    symbols = ['!', '@', '#', '$', '_', '-']
    for s in symbols:
        yield f"{name}{s}"
        yield f"{s}{name}"
        # simple insertion after first char
        if len(name) > 0:
            yield name[0] + s + name[1:]

def combine_with_common(name, words):
    for w in words:
        yield name + w
        yield w + name
        yield f"{name}{w}123"

def random_mutations(name, count=5):
    chars = list(name)
    pool = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%_-'
    for _ in range(count):
        i = random.randrange(len(chars))
        chars[i] = random.choice(pool)
        yield ''.join(chars)


def generate_candidates(company_name: str, ai_intensity: str = 'medium', max_candidates: int = 1000):
    """
    Generate a set of candidate passwords based on company_name and ai_intensity.
    This is a rule-based "AI mode" intended for demonstration (no ML).
    """
    seed = (company_name or "").strip()
    seed = ''.join(c for c in seed if c.isalnum() or c in "-_")
    if not seed:
        return []

    intensity = (ai_intensity or 'medium').lower()
    if intensity == 'low':
        target = min(max_candidates, 100)
    elif intensity == 'high':
        target = min(max_candidates, 5000)
    else:
        target = min(max_candidates, 1000)

    candidates = []
    
    # 1) Basic variants
    candidates.extend(list(basic_variants(seed)))

    # 2) Add suffixes
    # Note: Using set(candidates) is key here for expanding the variants generated above
    candidates.extend(add_suffixes(set(candidates), COMMON_SUFFIXES)) 

    # 3) Leet and symbols for medium+ and high
    if intensity in ('medium', 'high'):
        current_seeds = list(set(candidates))
        for c in current_seeds:
            for lv in leet_variants(c):
                candidates.append(lv)
            for s in insert_symbols(c):
                candidates.append(s)

    # 4) Combine with common words (medium+)
    if intensity in ('medium', 'high'):
        combination_seeds = list(set(candidates))
        if not combination_seeds: combination_seeds = [seed]
        
        for c in combination_seeds:
            for comb in combine_with_common(c if c else seed, COMMON_WORDS):
                candidates.append(comb)

    # 5) Random mutations for high intensity
    if intensity == 'high':
        for _ in range(300):
            for rm in random_mutations(seed, count=3):
                candidates.append(rm)

    # 6) Add year ranges if medium/high
    if intensity in ('medium', 'high'):
        years = [str(y) for y in range(2015, 2026)]
        for y in years:
            candidates.append(seed + y)
            candidates.append(seed + y + '!')

    # 7) Combine seed with small common suffix list
    for w in COMMON_WORDS:
        candidates.append(seed + w)
        candidates.append(w + seed)

    # Final cleanup: unique, reasonable length, and limit
    unique = []
    seen = set()
    for p in candidates:
        if not p:
            continue
        if len(p) > 40:
            continue
        if p in seen:
            continue
        seen.add(p)
        unique.append(p)
        if len(unique) >= target:
            break

    return unique

# --- RULE GENERATION FUNCTION (for dictionary mode) ---
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
    substitutions = [('o', '0'), ('a', '@'), ('e', '3'), ('s', '$'), ('i', '1')]
    for char, sub in substitutions:
        if char in word:
            # Replace only the first instance of the character
            yield word.replace(char, sub, 1)

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


# --- HASHING AND VERIFICATION LOGIC ---
def detect_hash_type(hash_str: str):
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
            # Use 100000 iterations for consistency
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


# --- NEW: ADVANCED INTELLIGENCE & COMPLIANCE ---

def calculate_shannon_entropy(password: str) -> float:
    """Calculates a simplified Shannon Entropy score for a password."""
    if not password:
        return 0.0
    
    char_sets = 0
    if re.search(r'[a-z]', password):
        char_sets += 26
    if re.search(r'[A-Z]', password):
        char_sets += 26
    if re.search(r'[0-9]', password):
        char_sets += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        char_sets += 32

    if char_sets == 0:
        return 0.0
        
    # Simplified Entropy calculation for scoring: H ≈ L * log2(N)
    return len(password) * (char_sets ** 0.5 if char_sets > 1 else 0) / 10


def check_compliance(password: str, company_name: str) -> dict:
    """Checks password against predefined policy rules."""
    
    # 1. Define Rules
    policy = {
        "min_length_12": len(password) >= 12,
        "no_company_name": company_name.lower() not in password.lower() if company_name else True,
        "has_special_char": bool(re.search(r'[^a-zA-Z0-9]', password)),
        "is_not_common_word": password.lower() not in COMMON_WORDS
    }
    
    # 2. Calculate Score
    score = sum(policy.values())
    policy['score'] = score
    policy['compliant'] = score >= 3 # Pass if 3 out of 4 policies are met

    return policy

def score_visualization(avg_entropy: float, compliance_rate: float) -> str:
    """Provides a simple A-F scorecard based on results."""
    # Logic: Higher compliance AND higher average entropy results in a better grade
    if compliance_rate >= 80 and avg_entropy > 5.0: # 5.0 is a reasonable mid-range score for the simplified calc
        return "A+"
    elif compliance_rate >= 60 and avg_entropy > 4.0:
        return "B"
    elif compliance_rate >= 40:
        return "C"
    elif compliance_rate >= 20:
        return "D"
    else:
        return "F"

def analyze_passwords(cracked_passwords: list, company_name: str = None):
    """Analyzes a list of cracked passwords for common weaknesses and classifies them."""
    analysis = {
        "common_patterns": {
            "contains_company_name_percent": 0.0,
            "ends_with_year_percent": 0.0,
            "is_all_lowercase_percent": 0.0
        },
        "vulnerability_classification": {
            "PII_Company_Info": 0,
            "Sequential_Predictable": 0,
            "Keyboard_Patterns": 0,
            "Other_Weak": 0
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
    
    pii_count = 0
    seq_count = 0
    keyboard_count = 0
    other_weak_count = 0
    classified_users = set()

    for item in cracked_passwords:
        pw = item['password']
        user = item.get('user', '')
        is_classified = False

        # --- Policy/Pattern Counts ---
        if company_name and company_name.lower() in pw.lower():
            company_name_count += 1
        
        if re.search(r'\d{4}$', pw):
            ends_with_year_count += 1
        
        if pw.islower():
            all_lowercase_count += 1

        # --- Vulnerability Classification Logic ---
        # 1. PII/Company Info (Check first, as it's often a policy violation)
        # Check if password contains company name OR parts of the username (simple check)
        username_part = user.split('_')[0].lower() # Simple split for cases like "alice_md5"
        if company_name and (company_name.lower() in pw.lower() or (len(username_part)>2 and username_part in pw.lower())):
             pii_count += 1
             is_classified = True

        # 2. Keyboard Patterns (Check next)
        if not is_classified and ('qwerty' in pw.lower() or 'asdfg' in pw.lower() or '1qaz' in pw.lower()):
             keyboard_count += 1
             is_classified = True

        # 3. Sequential/Predictable (Lower priority)
        if not is_classified and (re.search(r'(123|abc|xyz)', pw.lower()) or re.search(r'\d+$', pw) or pw.lower() in COMMON_WORDS):
             seq_count += 1
             is_classified = True

        # 4. Other Weak (Catch-all if not classified above)
        if not is_classified:
             other_weak_count += 1


    if count > 0: # Avoid division by zero
        analysis["common_patterns"]["contains_company_name_percent"] = round((company_name_count / count) * 100, 2)
        analysis["common_patterns"]["ends_with_year_percent"] = round((ends_with_year_count / count) * 100, 2)
        analysis["common_patterns"]["is_all_lowercase_percent"] = round((all_lowercase_count / count) * 100, 2)

    analysis["vulnerability_classification"]["PII_Company_Info"] = pii_count
    analysis["vulnerability_classification"]["Sequential_Predictable"] = seq_count
    analysis["vulnerability_classification"]["Keyboard_Patterns"] = keyboard_count
    analysis["vulnerability_classification"]["Other_Weak"] = other_weak_count

    return analysis

# --- CRACKING THREADS AND MASK GENERATOR (REMAIN UNCHANGED) ---

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

    groups = []
    i = 0
    while i < len(mask):
        token = mask[i:i+2] 
        if token in charsets:
            groups.append(charsets[token])
            i += 2
        else:
            # Handle invalid token or literal character that is not part of a pattern
            if token[0] in charsets: # Check for single character attempt
                print(f"Error: Single character mask token '{token[0]}' found. Please use the two-character format, e.g., '?l'.")
            else:
                print(f"Error: Invalid mask token '{token}' found. Please use ?l, ?u, ?d, or ?s.")
            return

    for combo in itertools.product(*groups):
        yield ''.join(combo)

def worker(job_q: queue.Queue, results_q: queue.Queue, user_hashes: Dict[str, str],
           user_types: Dict[str, str], found: Dict[str, str], found_lock: threading.Lock,
           stop_event: threading.Event, wid: int):
    # This remains the same: it takes candidates and checks them against all remaining hashes.
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


# --- MAIN EXECUTION ---

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash-file", required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--mode", required=True, choices=['dictionary', 'mask', 'ai']) 
    parser.add_argument("--wordlist", help="Path for dictionary mode")
    parser.add_argument("--mask", help="Mask pattern for mask mode")
    parser.add_argument("--company-name", help="Company name to check for in passwords.")
    parser.add_argument("--ai-intensity", help="Intensity for AI mode (low, medium, high).") 
    args = parser.parse_args()

    # --- Argument validation ---
    if args.mode == 'dictionary' and not args.wordlist:
        print(json.dumps({"error": "--wordlist is required for dictionary mode."}))
        return
    if args.mode == 'mask' and not args.mask:
        print(json.dumps({"error": "--mask is required for mask mode."}))
        return
    if args.mode == 'ai' and (not args.company_name or not args.ai_intensity):
        print(json.dumps({"error": "--company-name and --ai-intensity are required for AI mode."}))
        return
    
    # Basic file checks
    if not os.path.exists(args.hash_file):
        print(json.dumps({"error": f"Hash file '{args.hash_file}' does not exist."}))
        return
    if args.mode == 'dictionary' and not os.path.exists(args.wordlist):
        print(json.dumps({"error": f"Wordlist '{args.wordlist}' does not exist."}))
        return

    # Load Hashes
    with open(args.hash_file, "r") as f:
        user_hashes = json.load(f)

    all_audited_hashes = [{"user": u, "hash": h} for u, h in user_hashes.items()]

    # --- Initialize the report_data dictionary ---
    report_data = {
        "summary": {
            "total_hashes": len(user_hashes),
            "cracked_count": 0,
            "crack_rate_percent": 0.0,
            "duration_seconds": 0.0
        },
        "performance_benchmark": {},
        "cracked_passwords": [],
        "top_offenders": [], # New field for top 5 list
        "analysis": {},
        "advanced_policy_report": {}, # New top-level field for score
        "all_audited_hashes": all_audited_hashes 
    }

    # --- Setup worker bookkeeping ---
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
        t = threading.Thread(target=worker, args=(job_q, results_q, user_hashes, user_types, found, found_lock, stop_event, i + 1))
        t.daemon = True
        t.start()
        workers_list.append(t)

    # --- Producer logic (dictionary, mask, ai) ---
    producer_thread = None
    # (Dictionary, Mask, and AI Producers remain the same as before, feeding job_q)
    if args.mode == 'dictionary':
        def dict_producer():
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
            for candidate in mask_generator(args.mask):
                if stop_event.is_set(): break
                job_q.put(candidate)
        producer_thread = threading.Thread(target=mask_producer)
    elif args.mode == 'ai':
        def ai_producer():
            intensity = args.ai_intensity.lower()
            max_cands = 5000 if intensity == 'high' else (1000 if intensity == 'medium' else 200)
            
            generated = generate_candidates(args.company_name, intensity, max_candidates=max_cands)
            
            if not generated:
                # Fallback in case generation fails
                generated = [args.company_name, args.company_name + "123", args.company_name + "2024"]
                
            for candidate in generated:
                if stop_event.is_set(): break
                job_q.put(candidate)
        producer_thread = threading.Thread(target=ai_producer)

    if producer_thread:
        producer_thread.daemon = True
        producer_thread.start()

    start_time = time.time()

    # --- Collect results and build report_data ---
    try:
        while len(found) < len(user_hashes):
            try:
                user, cand, htype, wid = results_q.get(timeout=1.0)
            except queue.Empty:
                if producer_thread and not producer_thread.is_alive() and job_q.empty():
                    break
                continue

            # Store the found password
            report_data["cracked_passwords"].append({
                "user": user,
                "password": cand,
                "hash_type": htype
            })

            if htype in timing_data:
                timing_data[htype]['found_count'] += 1
                if timing_data[htype]['found_count'] == total_hashes_by_type.get(htype, 0):
                    timing_data[htype]['end_time'] = time.time()
                    
            results_q.task_done()
            
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        
        # Wait for producer to finish (if still running) and workers to empty the queue
        if producer_thread and producer_thread.is_alive():
            producer_thread.join(timeout=2)
        try:
            job_q.join() 
        except Exception:
            pass # Gracefully handle join exception

        duration = time.time() - start_time

        # --- Finalize Summary and Performance ---
        report_data["summary"]["duration_seconds"] = round(duration, 2)
        report_data["summary"]["cracked_count"] = len(found)
        if report_data["summary"]["total_hashes"] > 0:
            rate = (len(found) / len(user_hashes)) * 100
            report_data["summary"]["crack_rate_percent"] = round(rate, 2)

        for htype, data in timing_data.items():
            if data['end_time']:
                crack_duration = data['end_time'] - start_time
                report_data["performance_benchmark"][htype.upper()] = round(crack_duration, 4)
            
        # --- NEW: Advanced Policy & Intelligence Analysis ---
        
        total_entropy = 0.0
        total_compliant = 0
        
        # 1. Analyze Cracked Passwords (add entropy and compliance data)
        if report_data["cracked_passwords"]:
            for item in report_data["cracked_passwords"]:
                pw = item['password']
                entropy = calculate_shannon_entropy(pw)
                compliance = check_compliance(pw, args.company_name or "")
                
                item['entropy'] = round(entropy, 2)
                item['compliance'] = compliance
                
                total_entropy += entropy
                if compliance['compliant']:
                    total_compliant += 1
            
            # 2. Add Uncracked Hashes to Compliance Count (Assume they are compliant)
            uncracked_count = len(user_hashes) - len(found)
            total_compliant += uncracked_count 
            
            # 3. Calculate Final Scorecard
            avg_entropy = total_entropy / len(report_data["cracked_passwords"]) 
            compliance_rate = (total_compliant / len(user_hashes)) * 100
            scorecard = score_visualization(avg_entropy, compliance_rate)
            
            # 4. Finalize Advanced Report
            report_data["advanced_policy_report"] = {
                "scorecard": scorecard,
                "average_entropy_cracked": round(avg_entropy, 2),
                "total_compliant_rate": round(compliance_rate, 2),
                "policy_failed_count": len(user_hashes) - total_compliant,
            }

            # 5. Top Offenders (Deep Intelligence)
            password_counts = Counter(item['password'] for item in report_data["cracked_passwords"])
            report_data["top_offenders"] = [{"password": p, "count": c} for p, c in password_counts.most_common(5)]
            
            # 6. Vulnerability Classification (Deep Intelligence)
            analysis_results = analyze_passwords(report_data["cracked_passwords"], args.company_name)
            report_data["analysis"] = analysis_results

        else:
            # Handle case where 0 passwords were cracked
            report_data["advanced_policy_report"] = {
                "scorecard": "A+",
                "average_entropy_cracked": 0.0,
                "total_compliant_rate": 100.0,
                "policy_failed_count": 0,
                "note": "No passwords cracked. Assuming 100% compliance against this attack."
            }
            report_data["analysis"] = analyze_passwords([], args.company_name)

        # --- Output final JSON ---
        print(json.dumps(report_data, indent=4))

if __name__ == "__main__":
    main()
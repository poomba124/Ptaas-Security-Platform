import subprocess
import sys
from celery import Celery
from pymongo import MongoClient
from datetime import datetime
import json
import math
import string 

# --- NEW HELPER FUNCTIONS FOR SECURITY ANALYSIS ---

def calculate_shannon_entropy(password):
    if not password:
        return 0.0
    charset_size = 0
    # Calculate character set size based on characters present
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    # Using a common set of special characters
    if any(c in string.punctuation or c in string.whitespace for c in password):
        charset_size += 33 
    
    if charset_size == 0:
        return 0.0
    
    length = len(password)
    # Shannon Entropy formula: Length * log2(Charset Size)
    entropy = length * math.log2(charset_size)
    return round(entropy, 2)

def check_policy_violations(password, company_name=""):
    violations = []
    # Policy 1: Minimum Length (e.g., 12 characters)
    if len(password) < 12:
        violations.append("Too Short (< 12 chars)")
        
    # Policy 2: Requires Special Character
    special_chars = string.punctuation + string.whitespace
    if not any(c in special_chars for c in password):
        violations.append("Missing Special Character")
        
    # Policy 3: No Company Name
    if company_name and company_name.lower() in password.lower():
        violations.append("Contains Company Name")
        
    # Policy 4: At least one digit
    if not any(c in string.digits for c in password):
        violations.append("Missing Digit")
        
    return violations

def generate_security_score(average_entropy, total_violations_percent):
    """Assigns a security grade based on calculated metrics."""
    if average_entropy >= 80:
        if total_violations_percent < 5:
            return "A+"
        return "A"
    elif average_entropy >= 65:
        if total_violations_percent < 15:
            return "B"
        return "C+"
    elif average_entropy >= 50:
        return "C"
    else:
        return "D" if total_violations_percent < 40 else "F"

# --- DATABASE SETUP FOR THE WORKER ---
client = MongoClient('mongodb://127.0.0.1:27017/')
db = client['ptaas_db']
jobs_collection = db['audit_jobs']
# --- END DATABASE SETUP ---

# Initialize Celery
celery = Celery('tasks', config_source='celery_config')


@celery.task(bind=True) 
def run_cracking_task(self, attack_mode, **kwargs):
    """
    A Celery task that runs the cracking script, performs analysis, and updates the database.
    """
    task_id = self.request.id

    # --- 1. UPDATE STATUS TO RUNNING ---
    print(f"Worker picking up job {task_id}")
    jobs_collection.update_one(
        {'task_id': task_id},
        {'$set': {'status': 'RUNNING'}}
    )

    filepath = kwargs.get('filepath')
    company_name = kwargs.get('company_name') # Get company name for policy check
    
    # --- 2. BUILD THE BASE COMMAND ---
    command = [
        sys.executable,
        'cracker.py',
        '--hash-file', filepath,
        '--mode', attack_mode
    ]

    if company_name:
        command.extend(['--company-name', company_name])

    # --- 3. HANDLE MODE-SPECIFIC ARGUMENTS ---
    if attack_mode == 'dictionary':
        command.extend(['--wordlist', kwargs.get('wordlist_path')])
    elif attack_mode == 'mask':
        command.extend(['--mask', kwargs.get('mask')])
    elif attack_mode == 'ai':
        ai_intensity = kwargs.get('ai_intensity')
        if not ai_intensity:
            print("Warning: AI mode requires ai_intensity argument")
        command.extend(['--ai-intensity', ai_intensity])

    print("Running command:", " ".join(command))

    # --- 4. RUN THE CRACKER SCRIPT AS A SUBPROCESS ---
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        raw_output = result.stdout
        
        # Parse cracker output (expecting JSON)
        try:
            parsed_results = json.loads(raw_output)
            final_result_data = parsed_results
        except json.JSONDecodeError:
            final_result_data = {"error": "Cracker returned non-JSON data.", "raw_output": raw_output}
            
        # Get data needed for security analysis
        all_audited_hashes = final_result_data.get('all_audited_hashes', [])
        cracked_passwords = final_result_data.get('cracked_passwords', [])

        # --- 5. PERFORM SECURITY ANALYSIS CALCULATION ---
        total_audited_count = len(all_audited_hashes)
        
        total_entropy = 0
        violation_counts = {
            "Too Short (< 12 chars)": 0,
            "Missing Special Character": 0,
            "Contains Company Name": 0,
            "Missing Digit": 0
        }
        violating_users_set = set() 

        if cracked_passwords:
            for item in cracked_passwords:
                password = item.get('password', '') 
                user = item.get('user', '')
                
                # Entropy
                entropy = calculate_shannon_entropy(password)
                total_entropy += entropy

                # Policy Check on Cracked Passwords
                violations = check_policy_violations(password, company_name)
                
                if violations:
                    violating_users_set.add(user) 

                for v in violations:
                    if v in violation_counts:
                        violation_counts[v] += 1

            # Final Metrics
            average_entropy = round(total_entropy / len(cracked_passwords), 2)
            total_violating_users = len(violating_users_set)
            
            if total_audited_count > 0:
                total_violating_users_percent = round((total_violating_users / total_audited_count) * 100, 2)
            else:
                total_violating_users_percent = 0.0

            security_score = generate_security_score(average_entropy, total_violating_users_percent)

            # Insert the new analysis data structure into the final report
            final_result_data['security_analysis'] = {
                "total_audited": total_audited_count,
                "average_entropy": average_entropy,
                "security_score": security_score,
                "violations_by_policy": violation_counts,
                "total_violating_users_percent": total_violating_users_percent
            }
        else:
            # Handle case where nothing was cracked (assume policy is fine for uncracked)
            final_result_data['security_analysis'] = {
                "total_audited": total_audited_count,
                "average_entropy": 0.0,
                "security_score": "A+" if total_audited_count > 0 else "N/A", 
                "violations_by_policy": violation_counts,
                "total_violating_users_percent": 0.0
            }

        # --- 6. UPDATE DATABASE ON SUCCESS (SAVING THE ENTIRE JSON) ---
        jobs_collection.update_one(
            {'task_id': task_id},
            {
                '$set': {
                    'status': 'SUCCESS',
                    'result_data': json.dumps(final_result_data), 
                    'completed_at': datetime.utcnow()
                }
            }
        )
        return json.dumps(final_result_data) 

    except subprocess.CalledProcessError as e:
        error_output = e.stdout + e.stderr

        # --- 7. UPDATE DATABASE ON FAILURE ---
        jobs_collection.update_one(
            {'task_id': task_id},
            {
                '$set': {
                    'status': 'FAILURE',
                    'result_data': error_output,
                    'completed_at': datetime.utcnow()
                }
            }
        )
        return error_output
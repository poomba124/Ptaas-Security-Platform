# tasks.py

import subprocess
import sys
from celery import Celery
from pymongo import MongoClient
from datetime import datetime

# --- DATABASE SETUP FOR THE WORKER ---
client = MongoClient('mongodb://127.0.0.1:27017/')
db = client['ptaas_db']
jobs_collection = db['audit_jobs']
# --- END DATABASE SETUP ---

# Initialize Celery
celery = Celery('tasks', config_source='celery_config')

@celery.task(bind=True)  # Add bind=True to access task properties like ID
def run_cracking_task(self, attack_mode, **kwargs):
    """
    A Celery task that runs the cracking script and updates the database.
    """
    # Get the unique ID for this specific task execution
    task_id = self.request.id
    
    # --- 1. UPDATE STATUS TO RUNNING ---
    print(f"Worker picking up job {task_id}")
    jobs_collection.update_one(
        {'task_id': task_id},
        {'$set': {'status': 'RUNNING'}}
    )

    filepath = kwargs.get('filepath')

    command = [
        sys.executable,
        'cracker.py', 
        '--hash-file', filepath, 
        '--mode', attack_mode # Pass the mode to the script
    ]
    
    if attack_mode == 'dictionary':
        command.extend(['--wordlist', kwargs.get('wordlist_path')])
    elif attack_mode == 'mask':
        command.extend(['--mask', kwargs.get('mask')])
    # --- End command building ---
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout
        
        # Update DB on success
        jobs_collection.update_one(
            {'task_id': task_id},
            {'$set': {'status': 'SUCCESS', 'result_data': output, 'completed_at': datetime.utcnow()}}
        )
        return output
        
    except subprocess.CalledProcessError as e:
        error_output = e.stdout + e.stderr
        
        # Update DB on failure
        jobs_collection.update_one(
            {'task_id': task_id},
            {'$set': {'status': 'FAILURE', 'result_data': error_output, 'completed_at': datetime.utcnow()}}
        )
        return error_output
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
def run_cracking_task(self, filepath, wordlist_path):
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

    command = [
        sys.executable,
        'cracker.py', 
        '--hash-file', filepath, 
        '--wordlist', wordlist_path
    ]
    
    try:
        # Run the cracking script
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=True
        )
        output = result.stdout

        # --- 2. UPDATE STATUS TO SUCCESS ---
        print(f"Worker finished job {task_id} successfully.")
        jobs_collection.update_one(
            {'task_id': task_id},
            {'$set': {
                'status': 'SUCCESS',
                'result_data': output,
                'completed_at': datetime.utcnow()
            }}
        )
        return output
        
    except subprocess.CalledProcessError as e:
        error_output = e.stdout + e.stderr
        
        # --- 3. UPDATE STATUS TO FAILURE ---
        print(f"Worker job {task_id} failed.")
        jobs_collection.update_one(
            {'task_id': task_id},
            {'$set': {
                'status': 'FAILURE',
                'result_data': error_output,
                'completed_at': datetime.utcnow()
            }}
        )
        return error_output
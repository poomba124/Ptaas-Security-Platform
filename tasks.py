# tasks.py
import subprocess
import sys
from celery import Celery

# Initialize Celery and load config from the celery_config.py file
celery = Celery('tasks', config_source='celery_config')

@celery.task
def run_cracking_task(filepath, wordlist_path):
    """
    A Celery task that runs the cracking script in the background.
    """
    print(f"Worker starting job for hash file: {filepath}")
    
    command = [
        sys.executable,  # Use the same python interpreter
        'cracker.py', 
        '--hash-file', filepath, 
        '--wordlist', wordlist_path
    ]
    
    try:
        # Run the command and capture its output
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=True  # This will raise an exception if the script fails
        )
        output = result.stdout
        print(f"Worker finished job for hash file: {filepath}")
        return output
    except subprocess.CalledProcessError as e:
        # If the script returns an error, capture it
        error_output = e.stdout + e.stderr
        print(f"Worker job failed for {filepath}: {error_output}")
        return error_output
# app.py (Updated for Celery)
import os
import subprocess
import sys
from datetime import datetime
from flask import Flask, render_template, request, url_for, redirect
from tasks import run_cracking_task
from pymongo import MongoClient
import json

# --- DATABASE SETUP ---
# Connect to the MongoDB server running on Windows
client = MongoClient('mongodb://127.0.0.1:27017/')
# Select your database (it will be created if it doesn't exist)
db = client['ptaas_db']
# Select your collection for storing jobs
jobs_collection = db['audit_jobs']
# --- END DATABASE SETUP ---


app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/', methods=['GET', 'POST'])
def upload_and_process():
    if request.method == 'POST':
        # --- File Handling (check that a hash file was uploaded) ---
        if 'hash_file' not in request.files:
            return "No hash file part"
        hash_file = request.files['hash_file']
        if hash_file.filename == '':
            return "No selected hash file"
        
        # Save the uploaded hash file
        hash_filepath = os.path.join(app.config['UPLOAD_FOLDER'], hash_file.filename)
        hash_file.save(hash_filepath)

        # --- NEW: Read Attack Mode and Prepare Task Arguments ---
        attack_mode = request.form.get('attack_mode')
        company_name = request.form.get('company_name') # Get the company name
        task_args = {'filepath': hash_filepath, 'company_name': company_name} # Add it to the args

        
        if attack_mode == 'dictionary':
            # Use the default wordlist we have in our project folder
            task_args['wordlist_path'] = 'wordlist.txt' 
            # Note: The upload logic for a custom wordlist is not yet implemented
        elif attack_mode == 'mask':
            mask = request.form.get('mask')
            if not mask:
                return "Mask pattern is required for Mask Attack"
            task_args['mask'] = mask
        else:
            return "Invalid attack mode selected"

        # --- CORRECTED CALL: Launch Celery Task with keyword arguments ---
        task = run_cracking_task.delay(attack_mode=attack_mode, **task_args)
        
        # --- Create DB Record (this part is correct) ---
        job_document = {
            'task_id': task.id,
            'status': 'PENDING',
            'submitted_at': datetime.utcnow(),
            'hash_file_path': hash_file.filename,
            'result_data': None
        }
        jobs_collection.insert_one(job_document)
        
        return redirect(url_for('job_status', task_id=task.id))
    

    return render_template('index.html')

@app.route('/job/<task_id>')
def job_status(task_id):
    job = jobs_collection.find_one({'task_id': task_id})
    if not job:
        return "Job not found!", 404
        
    # --- NEW: Parse the JSON data before rendering ---
    if job.get('status') == 'SUCCESS' and job.get('result_data'):
        try:
            # Convert the JSON string from the DB into a Python dictionary
            job['result_data'] = json.loads(job['result_data'])
        except json.JSONDecodeError:
            # Handle cases where the output might not be valid JSON
            job['result_data'] = {"error": "Failed to parse result data."}
    # --- END NEW ---
            
    return render_template('job_status.html', job=job)
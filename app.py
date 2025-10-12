# app.py (Updated for Celery)
import os
import subprocess
import sys
from datetime import datetime
from flask import Flask, render_template, request, url_for, redirect
from tasks import run_cracking_task
from pymongo import MongoClient

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
        if 'hash_file' not in request.files:
            return "No file part"
        
        file = request.files['hash_file']
        if file.filename == '':
            return "No selected file"

        if file:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)

            wordlist_path = 'wordlist.txt'
            
            # Instead of running the subprocess, send the task to Celery.
            # .delay() sends the job to the queue and returns immediately.
            task = run_cracking_task.delay(filepath, wordlist_path)

            job_document = {
                'task_id': task.id,
                'status': 'PENDING',
                'submitted_at': datetime.utcnow(),
                'completed_at': None,
                'hash_file_path': file.filename,
                'result_data': None
            }

            jobs_collection.insert_one(job_document)
            
            # Redirect the user to a new page where they can see the task status.
            return redirect(url_for('job_status', task_id=task.id))

    return render_template('index.html')

@app.route('/job/<task_id>')
def job_status(task_id):
    # Find the job document in the database using its task_id
    job = jobs_collection.find_one({'task_id': task_id})

    if not job:
        return "Job not found!", 404

    return render_template('job_status.html', job=job)
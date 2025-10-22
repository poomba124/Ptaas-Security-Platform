import os

import subprocess

import sys

from datetime import datetime

from flask import Flask, render_template, request, url_for, redirect

from tasks import run_cracking_task

from pymongo import MongoClient

import json



# --- DATABASE SETUP ---

client = MongoClient('mongodb://127.0.0.1:27017/')

db = client['ptaas_db']

jobs_collection = db['audit_jobs']

# --- END DATABASE SETUP ---



app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/dashboard')
def dashboard():
    # Find all jobs in the collection and sort them by submission date (newest first)
    # Using sort() ensures recent jobs appear first.
    all_jobs = jobs_collection.find().sort('submitted_at', -1)

    # Render the dashboard template, passing the list of jobs to it
    return render_template('dashboard.html', jobs=all_jobs)


@app.route('/', methods=['GET', 'POST'])

def upload_and_process():

    if request.method == 'POST':

        # --- 1. File Handling ---

        if 'hash_file' not in request.files:

            return "No hash file part"

        hash_file = request.files['hash_file']

        if hash_file.filename == '':

            return "No selected hash file"



        # Save uploaded file

        hash_filepath = os.path.join(app.config['UPLOAD_FOLDER'], hash_file.filename)

        hash_file.save(hash_filepath)



        # --- 2. Read Attack Mode and Common Arguments ---

        attack_mode = request.form.get('attack_mode')

        company_name = request.form.get('company_name')  # shared across modes

        task_args = {'filepath': hash_filepath, 'company_name': company_name}



        # --- 3. Handle Mode-Specific Logic ---

        if attack_mode == 'dictionary':

            # Use default dictionary wordlist

            task_args['wordlist_path'] = 'wordlist.txt'



        elif attack_mode == 'mask':

            mask = request.form.get('mask')

            if not mask:

                return "Mask pattern is required for Mask Attack"

            task_args['mask'] = mask



        elif attack_mode == 'ai':

            # NEW: Handle AI Mode Inputs

            ai_intensity = request.form.get('ai_intensity')

            if not ai_intensity:

                return "AI intensity level is required for AI-Powered Smart Attack"

            if not company_name:

                return "Company name is required for AI-Powered Smart Attack"



            task_args['ai_intensity'] = ai_intensity

            # company_name already in task_args



        else:

            return "Invalid attack mode selected"



        # --- 4. Launch Celery Task ---

        task = run_cracking_task.delay(attack_mode=attack_mode, **task_args)



        # --- 5. Save Job Record in MongoDB ---

        job_document = {

            'task_id': task.id,

            'status': 'PENDING',

            'submitted_at': datetime.utcnow(),

            'hash_file_path': hash_file.filename,

            'result_data': None

        }

        jobs_collection.insert_one(job_document)



        return redirect(url_for('job_status', task_id=task.id))



    # Render upload page

    return render_template('index.html')





@app.route('/job/<task_id>')

def job_status(task_id):

    job = jobs_collection.find_one({'task_id': task_id})

    if not job:

        return "Job not found!", 404



    # --- Parse result data if job succeeded ---

    if job.get('status') == 'SUCCESS' and job.get('result_data'):

        try:

            job['result_data'] = json.loads(job['result_data'])

        except json.JSONDecodeError:

            job['result_data'] = {"error": "Failed to parse result data."}



    return render_template('job_status.html', job=job)


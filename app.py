# app.py (Updated for Celery)
import os
from flask import Flask, render_template, request, url_for, redirect
from tasks import run_cracking_task

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
            
            # Redirect the user to a new page where they can see the task status.
            return redirect(url_for('task_status', task_id=task.id))

    return render_template('index.html')

@app.route('/status/<task_id>')
def task_status(task_id):
    """
    This page shows the status of a background task.
    """
    # Ask Celery for the status of our task
    task = run_cracking_task.AsyncResult(task_id)
    
    # Render a template with the task's current state and result
    return render_template('task_status.html', task=task)
# app.py
import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for
import sys

# Configure the Flask App
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def upload_and_process():
    # If the form is submitted (a POST request)
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'hash_file' not in request.files:
            return "No file part"
        
        file = request.files['hash_file']
        if file.filename == '':
            return "No selected file"

        if file:
            # Save the uploaded file to the 'uploads' folder
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)

            # --- This is the core MVP logic ---
            # Call your script as a separate process
            # We use a small, known wordlist for this test MVP
            wordlist_path = 'wordlist.txt'
            
            command = [
                sys.executable,  # <--- INSTEAD OF 'python'
                'cracker.py', 
                '--hash-file', filepath, 
                '--wordlist', wordlist_path
            ]
            
            # Run the command and capture its output
            result = subprocess.run(command, capture_output=True, text=True)
            
            # The output from your script's print statements
            output = result.stdout + result.stderr

            # Render the results page, passing the output to the template
            return render_template('results.html', script_output=output)

    # If it's a GET request, just show the upload page
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
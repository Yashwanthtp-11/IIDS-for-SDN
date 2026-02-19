from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import json
import os
import logging

app = Flask(__name__)
# Allow cross-origin requests
CORS(app) 

# Suppress Flask's default logging to keep the terminal clean
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

DATA_FILE = 'dashboard_data.json'

@app.route('/')
def index():
    """Serves the index.html file."""
    try:
        return send_from_directory('.', 'index.html')
    except FileNotFoundError:
        return "Error: index.html not found.", 404


@app.route('/api/data')
def get_data():
    """Serves the live data from the JSON file."""
    if not os.path.exists(DATA_FILE):
        # Send empty data if the controller hasn't written the file yet
        return jsonify({"alerts": [], "traffic_stats": {"bytes_per_sec": 0}})
    
    try:
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        # Handle case where file is being read at the same time it's being written
        return jsonify({"alerts": [], "traffic_stats": {"bytes_per_sec": 0}})

if __name__ == '__main__':
    print("Dashboard server starting on http://127.0.0.1:5000")
    print("Open this URL in your browser.")
    app.run(host='127.0.0.1', port=5000)

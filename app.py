from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from influxdb_client import InfluxDBClient
import os
import subprocess

app = Flask(__name__, static_folder="frontend/public", static_url_path="/")
CORS(app)  # Allow frontend to access backend

# InfluxDB Credentials
TOKEN = "tlHycT1ShkNDVGL-qpZGZFSKxOaZDKp8zi3QcPBr7PadN-zPfHRIpaMfWCGvzLwrmKKcIpY7MWtN7UCuBCz52Q=="
ORG = "BE_Project"
BUCKET = "deepacketanalyser"
URL = "http://localhost:8086"

# Initialize InfluxDB Client
client = InfluxDBClient(url=URL, token=TOKEN, org=ORG)
query_api = client.query_api()

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Root of aipktanalyser/
BACKEND_DIR = os.path.join(BASE_DIR, "backend")  # backend folder
UPLOAD_PATH = os.path.join(BACKEND_DIR, "capture_file.pcap")  # Upload inside backend
MODEL_SCRIPT = os.path.join(BACKEND_DIR, "model_runner.py")  # Model script

@app.route("/")
def serve_dashboard():
    return send_from_directory(app.static_folder, "index.html")

@app.route('/scripts/<path:filename>')
def serve_scripts(filename):
    return send_from_directory(os.path.join(app.static_folder, "scripts"), filename)

@app.route('/fetch-data', methods=['GET'])
def fetch_data():
    try:
        query = f'''
        from(bucket: "{BUCKET}")
            |> range(start: -1d)
            |> filter(fn: (r) => r["_measurement"] == "packet_data")
            |> filter(fn: (r) => r["_field"] == "normal_count" or r["_field"] == "anomaly_count")
            |> aggregateWindow(every: 1h, fn: mean, createEmpty: false)
        '''

        result = query_api.query(org=ORG, query=query)

        data = []
        for table in result:
            for record in table.records:
                data.append({
                    "time": record.get_time(),
                    "field": record.get_field(),
                    "value": record.get_value()
                })

        return jsonify(data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 🔹 File Upload API
@app.route("/upload", methods=["POST"])
def upload_pcap():
    try:
        if "file" not in request.files:
            return jsonify({"message": "No file uploaded"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"message": "No file selected"}), 400

        # Ensure backend folder exists
        if not os.path.exists(BACKEND_DIR):
            os.makedirs(BACKEND_DIR)

        # Delete old file if exists
        if os.path.exists(UPLOAD_PATH):
            os.remove(UPLOAD_PATH)

        # Save new file inside backend
        file.save(UPLOAD_PATH)

        # Invoke model_runner.py asynchronously
        with open(os.path.join(BACKEND_DIR, "model_runner.log"), "w") as log_file:
            process = subprocess.Popen(["python3", MODEL_SCRIPT], cwd=BACKEND_DIR, stdout=log_file, stderr=log_file)

        return jsonify({"message": "File uploaded successfully! Processing started."})

    except Exception as e:
        return jsonify({"message": f"Upload failed! Error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)

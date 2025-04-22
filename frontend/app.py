from flask import Flask, jsonify
from influxdb_client import InfluxDBClient

app = Flask(__name__)

# InfluxDB Connection Details
INFLUX_URL = "http://localhost:8086"  # Change if different
INFLUX_TOKEN = "your-token"           # Set your actual token
INFLUX_ORG = "your-org"
INFLUX_BUCKET = "your-bucket"

client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
query_api = client.query_api()

@app.route('/fetch-data', methods=['GET'])
def fetch_data():
    try:
        query = f'from(bucket: "{INFLUX_BUCKET}") |> range(start: -1h)'
        tables = query_api.query(query)

        normal_count = 0
        anomaly_count = 0

        for table in tables:
            for record in table.records:
                if record.get_value() == "normal":
                    normal_count += 1
                elif record.get_value() == "anomaly":
                    anomaly_count += 1

        return jsonify({
            "normal_count": normal_count,
            "anomaly_count": anomaly_count
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)

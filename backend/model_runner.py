import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import time
import pickle
import os
import numpy as np
import influxdb_client
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import WriteOptions, SYNCHRONOUS

# Define required features
required_columns = [
    'Flow Packets/s', 'Protocol', 'ct_dst_ltm', 'ct_src_ltm',
    'Fwd Packet Length Range', 'ct_srv_dst', 'sbytes', 'Sload',
    'load_jit_interaction_dst', 'Bwd Packet Length Range',
    'Total Fwd Packets', 'dur', 'ct_dst_src_ltm', 'dbytes', 'ct_srv_src',
    'Label'
]

# Data structures for session tracking
flow_stats = defaultdict(list)
packet_timestamps = []
session_data = defaultdict(lambda: {"start_time": None, "end_time": None, "packet_count": 0, "bytes_sent": 0, "bytes_recv": 0})

# InfluxDB setup
token = "tlHycT1ShkNDVGL-qpZGZFSKxOaZDKp8zi3QcPBr7PadN-zPfHRIpaMfWCGvzLwrmKKcIpY7MWtN7UCuBCz52Q=="
org = "BE_Project"
url = "http://localhost:8086"
write_client = InfluxDBClient(url=url, token=token, org=org)
write_api = write_client.write_api(write_options=SYNCHRONOUS)  # Define write_api here

def extract_features(packet):
    """Extract features from a Scapy packet."""
    if not packet.haslayer(IP):
        return {col: 0 for col in required_columns}  # Skip non-IP packets

    ts = time.time()
    packet_timestamps.append(ts)

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto
    payload_len = len(packet) if hasattr(packet, 'payload') else 0

    src_port = dst_port = 0
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    session_key = (src_ip, dst_ip, protocol, src_port, dst_port)

    session = session_data[session_key]
    if session["start_time"] is None:
        session["start_time"] = ts
    session["end_time"] = ts
    session["packet_count"] += 1
    session["bytes_sent"] += payload_len
    session["bytes_recv"] += 0

    duration = session["end_time"] - session["start_time"]
    flow_packets_per_sec = session["packet_count"] / duration if duration > 0 else 1

    flow_stats['ct_dst_ltm'].append(dst_ip)
    flow_stats['ct_src_ltm'].append(src_ip)
    ct_dst_ltm = len(set(flow_stats['ct_dst_ltm']))
    ct_src_ltm = len(set(flow_stats['ct_src_ltm']))

    fwd_packet_length_range = max(payload_len, session["bytes_sent"]) - min(payload_len, session["bytes_sent"])
    bwd_packet_length_range = max(0, session["bytes_recv"])

    ct_srv_dst = sum(1 for key in session_data if key[1] == dst_ip and key[4] == dst_port)
    ct_srv_src = sum(1 for key in session_data if key[0] == src_ip and key[4] == dst_port)

    jitter = 0
    if len(packet_timestamps) > 1:
        jitter = packet_timestamps[-1] - packet_timestamps[-2]

    sload = session["bytes_sent"] / duration if duration > 0 else session["bytes_sent"]
    label = 0

    features = {
        'Flow Packets/s': flow_packets_per_sec,
        'Protocol': protocol,
        'ct_dst_ltm': ct_dst_ltm,
        'ct_src_ltm': ct_src_ltm,
        'Fwd Packet Length Range': fwd_packet_length_range,
        'ct_srv_dst': ct_srv_dst,
        'sbytes': session["bytes_sent"],
        'Sload': sload,
        'load_jit_interaction_dst': jitter,
        'Bwd Packet Length Range': bwd_packet_length_range,
        'Total Fwd Packets': session["packet_count"],
        'dur': duration,
        'ct_dst_src_ltm': len(set(flow_stats['ct_dst_ltm']) | set(flow_stats['ct_src_ltm'])),
        'dbytes': session["bytes_recv"],
        'ct_srv_src': ct_srv_src,
        'Label': label
    }

    return features

# Load pcap file
packets = rdpcap("capture_file.pcap")
df = pd.DataFrame([extract_features(pkt) for pkt in packets])
df.drop(columns=['Label'], inplace=True)

# Load pre-trained model
xgboost_model = pickle.load(open('xgboost_on_cicidsunswbinary.pkl', 'rb'))
xgboost_preds = xgboost_model.predict(df)

# Handle predictions
def handle_model_predictions(preds):
    if preds.ndim > 1:
        preds = np.argmax(preds, axis=1)
    return preds

xgboost_preds = handle_model_predictions(xgboost_preds)

# Count normal and anomaly packets
normal_count = np.sum(xgboost_preds == 0)
anomaly_count = np.sum(xgboost_preds == 1)

# Prepare data for InfluxDB
point = Point("packet_data") \
    .tag("type", "count") \
    .field("normal_count", normal_count) \
    .field("anomaly_count", anomaly_count)

# Write to InfluxDB
write_api.write(bucket="deepacketanalyser", org=org, record=point)

# Store anomaly packet information
anomaly_packets = df[xgboost_preds == 1]

# Create batch points for anomaly packets to improve performance
batch_points = []
for index, packet in anomaly_packets.iterrows():
    point = Point("anomaly_packet") \
        .tag("src_ip", packet['ct_src_ltm']) \
        .tag("dst_ip", packet['ct_dst_ltm']) \
        .field("flow_packets_per_sec", packet['Flow Packets/s']) \
        .field("protocol", packet['Protocol']) \
        .field("duration", packet['dur']) \
        .field("total_fwd_packets", packet['Total Fwd Packets']) \
        .field("sbytes", packet['sbytes']) \
        .field("sload", packet['Sload'])
    
    batch_points.append(point)

# Write the batch to InfluxDB in one go
if batch_points:
    write_api.write(bucket="deepacketanalyser", org=org, record=batch_points)

print("Data uploaded to InfluxDB successfully.")

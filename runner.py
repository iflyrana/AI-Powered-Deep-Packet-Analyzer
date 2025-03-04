import pandas as pd
import scapy.all as scapy
import pickle
import numpy as np

# Load the trained ML model
MODEL_PATH = "xgb_model_02032025"
with open(MODEL_PATH, "rb") as model_file:
    model = pickle.load(model_file)

# Function to extract packet features
def extract_features(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    extracted_data = []
    
    for packet in packets:
        if packet.haslayer(scapy.IP):
            features = {
                "Destination Port": packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else 0,
                "Flow Duration": 0,  # Placeholder, needs session tracking
                "Total Fwd Packets": 1,  # Placeholder, modify for full session tracking
                "Total Length of Fwd Packets": len(packet.payload),
                "Fwd Packet Length Max": len(packet.payload),
                "Fwd Packet Length Min": len(packet.payload),
                "Fwd Packet Length Mean": len(packet.payload),
                "Fwd Packet Length Std": 0,
                "Bwd Packet Length Max": 0,  # Placeholder, adjust for real backward packets
                "Bwd Packet Length Min": 0,
                "Bwd Packet Length Mean": 0,
                "Bwd Packet Length Std": 0,
                "Flow Bytes/s": 0,  # Placeholder, needs time tracking
                "Flow Packets/s": 0,
                "Flow IAT Mean": 0,  # Placeholder, inter-arrival time
                "Flow IAT Std": 0,
                "Flow IAT Max": 0,
                "Flow IAT Min": 0,
                "Fwd IAT Total": 0,
                "Fwd IAT Mean": 0,
                "Fwd IAT Std": 0,
                "Fwd IAT Max": 0,
                "Fwd IAT Min": 0,
                "Bwd IAT Total": 0,
                "Bwd IAT Mean": 0,
                "Bwd IAT Std": 0,
                "Bwd IAT Max": 0,
                "Bwd IAT Min": 0,
                "Fwd Header Length": len(packet[scapy.IP]),
                "Bwd Header Length": 0,
                "Fwd Packets/s": 0,
                "Bwd Packets/s": 0,
                "Min Packet Length": len(packet.payload),
                "Max Packet Length": len(packet.payload),
                "Packet Length Mean": len(packet.payload),
                "Packet Length Std": 0,
                "Packet Length Variance": 0,
                "FIN Flag Count": int(packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags & 0x01),
                "PSH Flag Count": int(packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags & 0x08),
                "ACK Flag Count": int(packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags & 0x10),
                "Average Packet Size": len(packet.payload),
                "Subflow Fwd Bytes": len(packet.payload),
                "Init_Win_bytes_forward": packet[scapy.TCP].window if packet.haslayer(scapy.TCP) else 0,
                "Init_Win_bytes_backward": 0,
                "act_data_pkt_fwd": 1,
                "min_seg_size_forward": 0,
                "Active Mean": 0,
                "Active Max": 0,
                "Active Min": 0,
                "Idle Mean": 0,
                "Idle Max": 0,
                "Idle Min": 0,
            }
            extracted_data.append(features)
    
    return pd.DataFrame(extracted_data)

# Path to the input PCAP file
PCAP_FILE = "traffic.pcap"

# Extract features from PCAP
feature_df = extract_features(PCAP_FILE)

#@Mihir change it to whatever comfortable for values that are absent
feature_df = feature_df.fillna(0)

# Ensure correct order of features before prediction
expected_features = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "PSH Flag Count", "ACK Flag Count", "Average Packet Size", "Subflow Fwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Max", "Active Min",
    "Idle Mean", "Idle Max", "Idle Min"
]
feature_df = feature_df.reindex(columns=expected_features, fill_value=0)

# Make predictions
predictions = model.predict(feature_df)

# Add predictions to the dataframe
feature_df["Attack Type"] = predictions

# Save results
feature_df.to_csv("prediction_results.csv", index=False)
print("Predictions saved to prediction_results.csv")

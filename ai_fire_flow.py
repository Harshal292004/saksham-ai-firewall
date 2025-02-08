from flask import Flask, request, jsonify
import joblib
import pandas as pd
import numpy as np

# Load the trained model (assumed to be a binary classifier: 0=benign, 1=malicious)
try:
    model = joblib.load("cic_scaler.pkl")
except Exception as e:
    raise RuntimeError("Could not load firewall model: " + str(e))

# Optionally, load the scaler if your model expects scaled inputs.
try:
    scaler = joblib.load("cic_scaler.pkl")
except Exception as e:
    # If scaler not available, you can set it to None.
    print("Scaler not loaded; proceeding without scaling:", e)
    scaler = None

# In‑memory set of blocked IPs (in production you’d likely use a persistent store)
blocked_ips = set()

# Define the expected feature names.
# (These should correspond to the columns you used when training your model.)
FEATURE_COLUMNS = [
    "destination_port",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_of_fwd_packets",
    "total_length_of_bwd_packets",
    "syn_flag_count",
    "ack_flag_count",
    "fin_flag_count",
    "fwd_packet_length",
    "fwd_packet_length_max",
    "bwd_packet_length_max",
    "flow_duration",
    "init_win_bytes_forward",
    "flow_packets",
    "down_up_ratio"
]

app = Flask(__name__)

def extract_features(data):
    """
    Convert raw data from the JSON payload into a dict of features.
    Adjust the conversion and defaults as needed.
    """
    features = {}
    try:
        features["destination_port"]       = int(data.get("destination_port", 0))
        features["total_fwd_packets"]        = int(data.get("total_fwd_packets", 0))
        features["total_backward_packets"]   = int(data.get("total_backward_packets", 0))
        features["total_length_of_fwd_packets"] = int(data.get("total_length_of_fwd_packets", 0))
        features["total_length_of_bwd_packets"] = int(data.get("total_length_of_bwd_packets", 0))
        features["syn_flag_count"]           = int(data.get("syn_flag_count", 0))
        features["ack_flag_count"]           = int(data.get("ack_flag_count", 0))
        features["fin_flag_count"]           = int(data.get("fin_flag_count", 0))
        features["fwd_packet_length"]        = int(data.get("fwd_packet_length", 0))
        features["fwd_packet_length_max"]    = int(data.get("fwd_packet_length_max", 0))
        features["bwd_packet_length_max"]    = int(data.get("bwd_packet_length_max", 0))
        features["flow_duration"]            = float(data.get("flow_duration", 0))
        features["init_win_bytes_forward"]   = int(data.get("init_win_bytes_forward", 0))
        features["flow_packets"]             = int(data.get("flow_packets", 0))
        features["down_up_ratio"]            = float(data.get("down_up_ratio", 0))
    except Exception as e:
        print("Error extracting features:", e)
    return features

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Receives a JSON payload with raw packet/flow data.
    Expects at least a 'src_ip' key (for the IP address) and the other keys needed for the model.
    """
    try:
        data = request.get_json()
        if data is None:
            return jsonify({"error": "No JSON payload provided"}), 400

        # The source IP (must be provided in the JSON by the browser extension or upstream logic)
        src_ip = data.get("src_ip")
        if not src_ip:
            return jsonify({"error": "Missing 'src_ip' in payload"}), 400

        # If this IP is already blocked, immediately return block.
        if src_ip in blocked_ips:
            return jsonify({"action": "block", "reason": "IP already blocked"})

        # Extract features from the provided data
        features = extract_features(data)
        # Create a DataFrame in the order of your training columns.
        df_features = pd.DataFrame([features], columns=FEATURE_COLUMNS)

        # Optionally, scale the features if a scaler was loaded.
        if scaler:
            df_features = pd.DataFrame(scaler.transform(df_features), columns=df_features.columns)

        # Make a prediction using the loaded model.
        # (Assuming your model returns 0 for benign, 1 for malicious.)
        prediction = model.predict(df_features)
        if prediction[0] == 1:
            blocked_ips.add(src_ip)
            return jsonify({"action": "block", "reason": "Malicious traffic detected"})
        else:
            return jsonify({"action": "allow", "reason": "Traffic is benign"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/blocked', methods=['GET'])
def get_blocked_ips():
    """
    Returns the list of currently blocked IP addresses.
    """
    return jsonify(list(blocked_ips))

if __name__ == '__main__':
    # Run the Flask server; in production, use a production-ready server.
    app.run(host='0.0.0.0', port=5000)

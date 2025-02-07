from flask import Flask, request, jsonify
from scapy.all import sniff
import tensorflow as tf
import numpy as np
import pandas as pd
from collections import defaultdict
import pickle
import threading
import time

app = Flask(__name__)

# Load the saved model and preprocessing components
model = tf.keras.models.load_model('cic_trained_model.h5')
with open('cic_scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)
with open('cic_class_names.pkl', 'rb') as f:
    class_names = pickle.load(f)
 
# Store flow statistics
flow_stats = defaultdict(lambda: {
    'fwd_packets': 0,
    'bwd_packets': 0,
    'fwd_bytes': 0,
    'bwd_bytes': 0,
    'syn_count': 0,
    'ack_count': 0,
    'fin_count': 0,
    'start_time': None,
    'packet_lengths_fwd': [],
    'packet_lengths_bwd': [],
    'init_win_bytes': 0
})

blocked_ips = set()
FLOW_TIMEOUT = 120  # 2 minutes

def extract_features(flow_id, stats):
    """Extract features from flow statistics"""
    if not stats['start_time']:
        return None
    
    flow_duration = time.time() - stats['start_time']
    if flow_duration == 0:
        return None

    features = {
        'destination port': flow_id[3],
        'total fwd packets': stats['fwd_packets'],
        'total backward packets': stats['bwd_packets'],
        'total length of fwd packets': stats['fwd_bytes'],
        'total length of bwd packets': stats['bwd_bytes'],
        'syn flag count': stats['syn_count'],
        'ack flag count': stats['ack_count'],
        'fin flag count': stats['fin_count'],
        'fwd packet length': np.mean(stats['packet_lengths_fwd']) if stats['packet_lengths_fwd'] else 0,
        'fwd packet length max': max(stats['packet_lengths_fwd']) if stats['packet_lengths_fwd'] else 0,
        'bwd packet length max': max(stats['packet_lengths_bwd']) if stats['packet_lengths_bwd'] else 0,
        'flow duration': flow_duration,
        'init_win_bytes_forward': stats['init_win_bytes'],
        'flow packets': stats['fwd_packets'] + stats['bwd_packets'],
        'down/up ratio': (stats['bwd_bytes'] / stats['fwd_bytes']) if stats['fwd_bytes'] > 0 else 0
    }
    
    return features

def predict_flow(features):
    """Predict if a flow is malicious"""
    if features is None:
        return False
        
    df = pd.DataFrame([features])
    scaled_features = scaler.transform(df)
    prediction = model.predict(scaled_features)
    predicted_class = np.argmax(prediction[0])
    
    # Assuming class_names contains the mapping of classes where benign traffic is labeled as such
    return class_names[predicted_class].lower() != 'benign'

def packet_callback(packet):
    """Process captured packets and update flow statistics"""
    if not hasattr(packet, 'ip'):
        return

    # Create flow ID (5-tuple)
    if hasattr(packet, 'tcp'):
        proto = 'tcp'
        sport = packet.sport
        dport = packet.dport
    elif hasattr(packet, 'udp'):
        proto = 'udp'
        sport = packet.sport
        dport = packet.dport
    else:
        return

    flow_id = (packet.src, packet.dst, proto, dport, sport)
    
    # Initialize flow if new
    if flow_stats[flow_id]['start_time'] is None:
        flow_stats[flow_id]['start_time'] = time.time()
        if hasattr(packet, 'tcp'):
            flow_stats[flow_id]['init_win_bytes'] = packet.window

    # Update packet counts and bytes
    if packet.src == flow_id[0]:  # Forward direction
        flow_stats[flow_id]['fwd_packets'] += 1
        flow_stats[flow_id]['fwd_bytes'] += len(packet)
        flow_stats[flow_id]['packet_lengths_fwd'].append(len(packet))
    else:  # Backward direction
        flow_stats[flow_id]['bwd_packets'] += 1
        flow_stats[flow_id]['bwd_bytes'] += len(packet)
        flow_stats[flow_id]['packet_lengths_bwd'].append(len(packet))

    # Update TCP flags
    if hasattr(packet, 'tcp'):
        if packet.tcp.flags & 0x02:  # SYN
            flow_stats[flow_id]['syn_count'] += 1
        if packet.tcp.flags & 0x10:  # ACK
            flow_stats[flow_id]['ack_count'] += 1
        if packet.tcp.flags & 0x01:  # FIN
            flow_stats[flow_id]['fin_count'] += 1

    # Extract features and predict
    features = extract_features(flow_id, flow_stats[flow_id])
    if features and predict_flow(features):
        blocked_ips.add(flow_id[0])  # Block source IP

def cleanup_flows():
    """Remove expired flows"""
    while True:
        current_time = time.time()
        expired_flows = [
            flow_id for flow_id, stats in flow_stats.items()
            if stats['start_time'] and (current_time - stats['start_time']) > FLOW_TIMEOUT
        ]
        for flow_id in expired_flows:
            del flow_stats[flow_id]
        time.sleep(60)  # Check every minute

@app.route('/status')
def get_status():
    """Get firewall status and blocked IPs"""
    return jsonify({
        'blocked_ips': list(blocked_ips),
        'active_flows': len(flow_stats),
        'status': 'running'
    })

@app.route('/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    """Unblock an IP address"""
    if ip in blocked_ips:
        blocked_ips.remove(ip)
        return jsonify({'message': f'IP {ip} unblocked'})
    return jsonify({'message': f'IP {ip} was not blocked'}), 404

def start_packet_capture():
    """Start packet capture in a separate thread"""
    sniff(prn=packet_callback, store=0)

if __name__ == '__main__':
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_flows, daemon=True)
    cleanup_thread.start()
    
    # Start packet capture thread
    capture_thread = threading.Thread(target=start_packet_capture, daemon=True)
    capture_thread.start()
    
    # Start Flask server
    app.run(host='0.0.0.0', port=5000)
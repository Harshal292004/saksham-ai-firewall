from flask import Flask, request, jsonify
import joblib
import pandas as pd

app = Flask(__name__)
model = joblib.load("firewall.pkl")
blocked_ips = set()

@app.route('/analyze', methods=['POST'])
def analyze_request():
    """Endpoint to analyze request features"""
    try:
        data = request.json
        features = extract_features(data)
        prediction = model.predict(pd.DataFrame([features]))
        
        if prediction[0] == 1:
            blocked_ips.add(data['src_ip'])
            return jsonify({"action": "block", "reason": "Malicious traffic detected"})
            
        return jsonify({"action": "allow"})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/blocked', methods=['GET'])
def get_blocked_ips():
    """Endpoint to retrieve blocked IPs"""
    return jsonify(list(blocked_ips))

def extract_features(data):
    """Extract features from request metadata"""
    return {
        'protocol_type': data.get('protocol', 0),
        'src_bytes': data.get('content_length', 0),
        'dst_bytes': data.get('response_size', 0),
        'request_count': data.get('request_count', 1),
        'http_method': data.get('method', 0),
        'url_length': len(data.get('url', '')),
        # Add more features based on your model requirements
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
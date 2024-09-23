import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Initial allowed IP pairs (hardcoded)
allowed_pairs = [
    ("192.168.0.100", "172.16.0.100"),
    ("192.168.0.100", "172.16.0.200")
]

# Flush the iptables FORWARD chain and apply the allowed rules
def setup_iptables():
    # Clear any existing forwarding rules first (optional, to start clean)
    os.system("iptables -F FORWARD")

    # Allow forwarding for each allowed pair
    for source_ip, dest_ip in allowed_pairs:
        print(f"Allowing forwarding from {source_ip} to {dest_ip}")
        os.system(f"iptables -A FORWARD -s {source_ip} -d {dest_ip} -j ACCEPT")

    # Block all other traffic by default
    os.system("iptables -A FORWARD -j DROP")
    print("Blocked all other forwarding traffic")

# Function to add an IP pair to iptables and the allowed pairs list
def add_ip_pair(source_ip, dest_ip):
    if (source_ip, dest_ip) not in allowed_pairs:
        allowed_pairs.append((source_ip, dest_ip))
        os.system(f"iptables -A FORWARD -s {source_ip} -d {dest_ip} -j ACCEPT")
        print(f"Allowed new pair: {source_ip} -> {dest_ip}")
        return True
    return False

# Function to remove an IP pair from iptables and the allowed pairs list
def remove_ip_pair(source_ip, dest_ip):
    if (source_ip, dest_ip) in allowed_pairs:
        allowed_pairs.remove((source_ip, dest_ip))
        os.system(f"iptables -D FORWARD -s {source_ip} -d {dest_ip} -j ACCEPT")
        print(f"Removed pair: {source_ip} -> {dest_ip}")
        return True
    return False

# Flask route to handle updates from the master node
@app.route('/update-pairs', methods=['POST'])
def update_pairs():
    data = request.json
    action = data.get('action')  # should be "allow" or "deny"
    source_ip = data.get('source_ip')
    dest_ip = data.get('dest_ip')

    if not source_ip or not dest_ip or action not in ['allow', 'deny']:
        return jsonify({"error": "Invalid data"}), 400

    if action == 'allow':
        if add_ip_pair(source_ip, dest_ip):
            return jsonify({"status": "allowed", "source_ip": source_ip, "dest_ip": dest_ip}), 200
        else:
            return jsonify({"status": "already allowed"}), 200

    elif action == 'deny':
        if remove_ip_pair(source_ip, dest_ip):
            return jsonify({"status": "denied", "source_ip": source_ip, "dest_ip": dest_ip}), 200
        else:
            return jsonify({"status": "pair not found"}), 200

# Main function to run the Flask app and set up initial iptables
if __name__ == "__main__":
    # Setup initial iptables rules
    setup_iptables()

    # Start Flask server to listen for updates from master node
    app.run(host="0.0.0.0", port=5000)

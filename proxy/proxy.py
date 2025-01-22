import os
import socket
from scapy.all import sniff
from collections import defaultdict
import paho.mqtt.client as mqtt
import time
import threading
import json
from time import sleep

# List of allowed IP pairs: (Source IP, Destination IP/Name)
allowed_pairs = []
proxy_ip = None

# Threshold for packet count
PACKET_THRESHOLD = 5

# IPs that are internal
ignored_ips = {"172.18.0.10", "172.18.0.30"}

# Packet dictionary for each client IP
packet_counts = defaultdict(int)

# Interface for sniffing packets
INTERFACE = "eth0"

# MQTT Broker details
MQTT_BROKER = "172.18.0.60"
MQTT_PORT = 1883
MQTT_TOPIC_COMMAND = "proxy/command"
MQTT_TOPIC_RESPONSE = "proxy/response"
mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

# Get the Proxy container's IP address
def get_proxy_ip():
    return os.popen("hostname -I").read().strip()

# Function to set up nftables with default drop policy and NAT configuration
def setup_nftables():
    # Add NAT table
    os.system("nft add table ip nat")

    # Add prerouting chain (for incoming NAT)
    os.system("nft add chain ip nat prerouting { type nat hook prerouting priority -100 \\; }")

    # Add postrouting chain (for outgoing NAT)
    os.system("nft add chain ip nat postrouting { type nat hook postrouting priority 100 \\; }")

    print("nftables initialized with default rules.")

# Function to apply DNAT and SNAT rules using nftables
def apply_filter_rules(client_ip, nest_ip):
    # DNAT
    os.system(f"nft add rule ip nat prerouting iifname eth0 ip saddr {client_ip} ip daddr {proxy_ip} tcp dport 5000 dnat to {nest_ip}")
    # SNAT
    os.system(f"nft add rule ip nat postrouting oifname eth0 ip saddr {client_ip} ip daddr {nest_ip} snat to {proxy_ip}")
    print(f"Added NAT rules: {client_ip} -> {nest_ip}")

# Function to add a new client-server pair and apply forwarding rules
def add_access_rule(client_ip, nest_ip):
    if (client_ip, nest_ip) not in allowed_pairs:
        allowed_pairs.append((client_ip, nest_ip))
        apply_filter_rules(client_ip, nest_ip)
        return True
    return False

# Function to remove a specific IP rule from nftables
def revoke_access_rule(client_ip, nest_ip):
    # Find and delete DNAT rule
    os.system(f"nft delete rule nat prerouting handle $(nft --handle list ruleset | egrep 'iifname \"eth0\" ip saddr {client_ip} ip daddr {proxy_ip} tcp dport 5000 dnat to {nest_ip}' | rev | cut -d' ' -f1 | rev)")

    # Find and delete SNAT rule
    os.system(f"nft delete rule nat postrouting handle $(nft --handle list ruleset | egrep 'oifname \"eth0\" ip saddr {client_ip} ip daddr {nest_ip} snat to {proxy_ip}' | rev | cut -d' ' -f1 | rev)")

    print(f"Revoked NAT rules: {client_ip} -> {nest_ip}")

# Function to analyze each packet
def packet_handler(packet):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        src_ip = packet["IP"].src
        tcp_layer = packet["TCP"]

        if src_ip in ignored_ips:
            return
        if src_ip == proxy_ip:
            return
        
        # Check if the packet is a SYN packet
        if tcp_layer.flags == "S":  # SYN flag
            # Increment packet count for this client IP
            packet_counts[src_ip] += 1
            
            # Check if the packet count exceeds the threshold
            if packet_counts[src_ip] > PACKET_THRESHOLD:
                message = f"[ALERT] Potential SYN flood detected from {src_ip}. SYN count: {packet_counts[src_ip]}"
                print(message)
                mqtt_client.publish(MQTT_TOPIC_RESPONSE, json.dumps({"proxy_ip": proxy_ip, "action": "alert", "client_ip": src_ip, "message": message}))
                # Take further action if desired, such as logging or blocking the source

def packet_counting_thread_func():
    sniff(iface=INTERFACE, prn=packet_handler, store=False)

# MQTT message handler
def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())

        received_proxy_ip = payload.get("proxy_ip")
        if received_proxy_ip != proxy_ip:
            return
        
        action = payload.get("action")
        client_ip = payload.get("client_ip")
        nest_ip = payload.get("nest_ip")

        if action == "allow":
            print(f"Received allow command for {client_ip} -> {nest_ip}")
            if add_access_rule(client_ip, nest_ip):
                response = {"proxy_ip": proxy_ip, "action": "allowed", "client_ip": client_ip}
            else:
                response = {"proxy_ip": proxy_ip, "action": "already_allowed", "client_ip": client_ip}

        elif action == "deny":
            print(f"Received deny command for {client_ip} -> {nest_ip}")
            if (client_ip, nest_ip) in allowed_pairs:
                revoke_access_rule(client_ip, nest_ip)
                allowed_pairs.remove((client_ip, nest_ip))
                response = {"proxy_ip": proxy_ip, "action": "revoked", "client_ip": client_ip}
            else:
                response = {"proxy_ip": proxy_ip, "action": "not_found", "client_ip": client_ip}

        # Publish the response to the response topic
        mqtt_client.publish(MQTT_TOPIC_RESPONSE, json.dumps(response))
    except Exception as e:
        print(f"Error processing message: {e}")

def on_connect(client, userdata, flags, rc, properties):
        if rc == 0:
            print("Connected to MQTT broker.")
            client.subscribe(MQTT_TOPIC_COMMAND)
            print(f"Subscribed to topic {MQTT_TOPIC_COMMAND}")  # Debugging
        else:
            print(f"Failed to connect to MQTT broker with code {rc}")

def setup_mqtt():
    global proxy_ip
    proxy_ip = get_proxy_ip()

    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    print(f"Proxy service running at {proxy_ip}")

if __name__ == "__main__":

    sleep(5)
    # Starting Scapy sniffing
    threading.Thread(target=packet_counting_thread_func).start()
    
    # Setup initial nftables rules
    setup_nftables()

    # Start MQTT communication
    setup_mqtt()
    mqtt_client.loop_forever(retry_first_connection=True)

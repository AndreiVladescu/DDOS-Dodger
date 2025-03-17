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
packet_threshold = 15
time_period = 60  # Time period in seconds

# IPs that are internal
ignored_ips = {"172.18.0.10", "172.18.0.30"}

# Structures to track packet counts and timestamps
packet_counts = defaultdict(lambda: {"tcp": 0, "udp": 0})
last_reset = time.time()

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
    os.system(f"nft add rule ip nat prerouting iifname eth0 ip saddr {client_ip} ip daddr {proxy_ip} tcp dport 80 dnat to {nest_ip}")
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
    os.system(f"nft delete rule nat prerouting handle $(nft --handle list ruleset | egrep 'iifname \"eth0\" ip saddr {client_ip} ip daddr {proxy_ip} tcp dport 80 dnat to {nest_ip}' | rev | cut -d' ' -f1 | rev)")

    # Find and delete SNAT rule
    os.system(f"nft delete rule nat postrouting handle $(nft --handle list ruleset | egrep 'oifname \"eth0\" ip saddr {client_ip} ip daddr {nest_ip} snat to {proxy_ip}' | rev | cut -d' ' -f1 | rev)")

    print(f"Revoked NAT rules: {client_ip} -> {nest_ip}")

# Function to find the pair given one IP
def find_pair(ip, allowed_pairs):
    for pair in allowed_pairs:
        if ip in pair:
            return pair
    return None

def get_nest_ip(pair, client_ip):
    if pair[0] == client_ip:
        return pair[1]
    return pair[0]

# Function to reset counts periodically
def reset_counts():
    global last_reset
    current_time = time.time()
    if current_time - last_reset > time_period:
        packet_counts.clear()
        last_reset = current_time

# Function to analyze each packet
def packet_handler(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src

        # Ignore internal or proxy IPs
        if src_ip in ignored_ips or src_ip == proxy_ip:
            return
        
        reset_counts()  # Reset counts periodically

        # SYN Flood Detection
        if packet.haslayer("TCP") and packet["TCP"].flags == "S":  # SYN flag
            packet_counts[src_ip]["tcp"] += 1
            if packet_counts[src_ip]["tcp"] > packet_threshold:
                nest_ip = get_nest_ip(find_pair(src_ip, allowed_pairs), src_ip)
                message = f"Potential SYN flood detected from {src_ip} while connecting to {nest_ip}. TCP count: {packet_counts[src_ip]['tcp']}"
                mqtt_client.publish(MQTT_TOPIC_RESPONSE, json.dumps({
                    "proxy_ip": proxy_ip,
                    "nest_ip": nest_ip,
                    "action": "alert-revoke",
                    "client_ip": src_ip,
                    "message": message
                }))
                packet_counts[src_ip]["tcp"] = 0

        # UDP Flood Detection
        elif packet.haslayer("UDP"):
            packet_counts[src_ip]["udp"] += 1
            if packet_counts[src_ip]["udp"] > packet_threshold:
                nest_ip = get_nest_ip(find_pair(src_ip, allowed_pairs), src_ip)
                message = f"Potential UDP flood detected from {src_ip} while connecting to {nest_ip}. UDP count: {packet_counts[src_ip]['udp']}"
                mqtt_client.publish(MQTT_TOPIC_RESPONSE, json.dumps({
                    "proxy_ip": proxy_ip,
                    "nest_ip": nest_ip,
                    "action": "alert-revoke",
                    "client_ip": src_ip,
                    "message": message
                }))
                packet_counts[src_ip]["udp"] = 0

def packet_counting_thread_func():
    sniff(iface=INTERFACE, prn=packet_handler, store=False)

# MQTT message handler
def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        received_proxy_ip = payload.get("proxy_ip")
        print(f"Received message for {received_proxy_ip}")

        if received_proxy_ip != proxy_ip:
            return
        
        print(f"Processing message: {payload}")

        action = payload.get("action")
        client_ip = payload.get("client_ip")
        nest_ip = payload.get("nest_ip")

        if action == "allow":
            print(f"Received allow command for {client_ip} -> {nest_ip}")
            if add_access_rule(client_ip, nest_ip):
                response = {"action": "allowed", 
                            "client_ip": client_ip, 
                            "nest_ip": nest_ip, 
                            "proxy_ip": proxy_ip}
            else:
                response = {"action": "already_allowed", 
                            "client_ip": client_ip, 
                            "nest_ip": nest_ip, 
                            "proxy_ip": proxy_ip}

        elif action == "revoke":
            print(f"Received revoke command for {client_ip} -> {nest_ip}")
            if (client_ip, nest_ip) in allowed_pairs:
                revoke_access_rule(client_ip, nest_ip)
                allowed_pairs.remove((client_ip, nest_ip))
                response = {"action": "revoked", 
                            "client_ip": client_ip, 
                            "nest_ip": nest_ip, 
                            "proxy_ip": proxy_ip}
            else:
                response = {"action": "not_found", 
                            "client_ip": client_ip, 
                            "nest_ip": nest_ip, 
                            "proxy_ip": proxy_ip}

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

# Benchmark function to preload users
def preload_users():
    for i in range (0, 255):
        add_access_rule(f'10.0.0.{i}','172.18.0.30')

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

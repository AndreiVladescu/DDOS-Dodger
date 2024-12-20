import os
import socket
from scapy.all import sniff
from collections import defaultdict
import time
import threading

# List of allowed IP pairs: (Source IP, Destination IP/Name)
allowed_pairs = []
proxy_ip = None

# Threshold for packet count
PACKET_THRESHOLD = 5

# Packet dictionary for each client IP
packet_counts = defaultdict(int)

# Interface for sniffing packets
INTERFACE = "eth0"

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
    os.system(f"nft delete rule nat prerouting handle $( nft --handle list ruleset | egrep 'iifname \"eth0\" ip saddr {client_ip} ip daddr {proxy_ip} tcp dport 5000 dnat to {nest_ip}' | rev | cut -d' ' -f1 | rev)")

    # Find and delete SNAT rule
    os.system(f"nft delete rule nat postrouting handle $(nft --handle list ruleset | egrep 'oifname \"eth0\" ip saddr {client_ip} ip daddr {nest_ip} snat to {proxy_ip}' | rev | cut -d' ' -f1 | rev)")

    print(f"Revoked NAT rules: {client_ip} -> {nest_ip}")

# Function to analyze each packet
def packet_handler(packet):
    if packet.haslayer("IP"):  # Check if the packet has an IP layer
        src_ip = packet["IP"].src
        
        # Increment packet count for this client IP
        packet_counts[src_ip] += 1

        # Check if the packet count exceeds the threshold
        if packet_counts[src_ip] > PACKET_THRESHOLD:
            print(f"[ALERT] Potential DOS detected from {src_ip}. Packet count: {packet_counts[src_ip]}")
            # Take further action if desired, such as logging or alerting
            # You can also reset the count for this IP if necessary

def packet_counting_thread_func():
    sniff(iface=INTERFACE, prn=packet_handler, store=False)

# TCP server to listen for updates from the master
def start_tcp_server():
    global proxy_ip

    # Define server address and port
    host = '0.0.0.0'  # Listen on all available network interfaces
    port = 6000        # Custom port for the Master comms

    proxy_ip = get_proxy_ip()
    # Create the TCP server socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()

        print(f"Proxy TCP server listening on {host}:{port}")

        while True:
            # Wait for a connection from the master
            client_socket, addr = server_socket.accept()
            with client_socket:
                print(f"Connected by {addr}")
                
                # Receive the message from the master
                data = client_socket.recv(1024).decode()
                if not data:
                    break
                
                # The message should be in the format "allow <source_ip> <dest_ip>"
                action, client_ip, nest_ip = data.split()

                print(f"Received command: {action} for {client_ip} -> {nest_ip}")

                if action == "allow":
                    if add_access_rule(client_ip, nest_ip):
                        client_socket.sendall(b"IP pair allowed.\n")
                    else:
                        client_socket.sendall(b"IP pair already allowed.\n")

                elif action == "deny":
                    revoke_access_rule(client_ip, nest_ip)
                    
                    # Remove the IP pair from the allowed list
                    allowed_pairs.remove((client_ip, nest_ip))
                    client_socket.sendall(b"IP pair removed.\n")
                else:
                    client_socket.sendall(b"Invalid action.\n")

if __name__ == "__main__":

    # Starting Scapy sniffing
    threading.Thread(target=packet_counting_thread_func).start()
    
    
    # Setup initial nftables rules
    setup_nftables()

    # Start the TCP server to listen for updates from the master
    start_tcp_server()

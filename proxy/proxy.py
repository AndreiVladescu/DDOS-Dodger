import os
import socket

# List of allowed IP pairs: (Source IP, Destination IP/Name)
allowed_pairs = []

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

    # Add DNAT rule to forward traffic on TCP port 5000 to 172.18.0.30
    os.system("nft add rule ip nat prerouting iifname eth0 tcp dport 5000 dnat to 172.18.0.30")

    # Add masquerade rule for traffic going to 172.18.0.30
    os.system("nft add rule ip nat postrouting ip daddr 172.18.0.30 masquerade")

    # Create inet filter table for filtering
    os.system("nft add table inet filter")

    # Add input chain to filter traffic (policy drop by default)
    os.system("nft add chain inet filter input { type filter hook input priority 0 \\; policy drop \\; }")

    # Allow only master to access port 6000 (proxy itself, no forwarding)
    os.system("nft add rule inet filter input ip saddr 172.18.0.10 tcp dport 6000 accept")

    print("nftables initialized with default rules.")

# Function to apply DNAT and SNAT rules using nftables
def apply_filter_rules(source_ip, dest_ip):
    '''
    # Allow traffic from 172.18.0.200 to access port 5000 (proxy and forward to .30)
    os.system("nft add rule inet filter input ip saddr 172.18.0.200 tcp dport 5000 accept")
    '''

    os.system(f'nft add rule inet filter input ip saddr {source_ip} tcp dport 5000 accept')

    print(f"Added NAT rules: {source_ip} -> {dest_ip}")

# Function to add a new client-server pair and apply forwarding rules
def add_ip_pair(source_ip, dest_ip):
    if (source_ip, dest_ip) not in allowed_pairs:
        allowed_pairs.append((source_ip, dest_ip))
        apply_filter_rules(source_ip, dest_ip)
        return True
    return False

# Function to remove a specific IP rule from nftables
def remove_ip(source_ip, dest_ip):

    allowed_pairs.remove((source_ip, dest_ip))
    os.system(f'nft delete rule inet filter input ip saddr {source_ip} tcp dport 5000 accept')

    print(f"Removed NAT rules: {source_ip} -> {dest_ip}")

# TCP server to listen for updates from the master
def start_tcp_server():
    # Define server address and port
    host = '0.0.0.0'  # Listen on all available network interfaces
    port = 6000        # Arbitrary port for the TCP server

    #add_ip_pair("172.18.0.100", "172.18.0.30")

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
                action, source_ip, dest_ip = data.split()

                if action == "allow":
                    if add_ip_pair(source_ip, dest_ip):
                        client_socket.sendall(b"IP pair allowed.\n")
                    else:
                        client_socket.sendall(b"IP pair already allowed.\n")

                elif action == "deny":
                    remove_ip(source_ip, dest_ip)

                    client_socket.sendall(b"IP pair removed.\n")

                else:
                    client_socket.sendall(b"Invalid action.\n")

if __name__ == "__main__":
    # Setup initial nftables rules
    setup_nftables()

    # Start the TCP server to listen for updates from the master
    start_tcp_server()

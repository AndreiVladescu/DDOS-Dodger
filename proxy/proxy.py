import os
import socket

# List of allowed IP pairs: (Source IP, Destination IP/Name)
allowed_pairs = []
proxy_ip = None

# Get the Proxy container's IP address
def get_proxy_ip():
    return os.popen("hostname -I").read().strip()

# Function to set up nftables with default drop policy and NAT configuration
def setup_nftables():
    client_ip = "172.18.0.100"
    server_ip = "172.18.0.30"
    proxy_ip = get_proxy_ip()
    master_ip = "172.18.0.10"

    # Add NAT table
    os.system("nft add table ip nat")

    # Add prerouting chain (for incoming NAT)
    os.system("nft add chain ip nat prerouting { type nat hook prerouting priority -100 \\; }")

    # Add postrouting chain (for outgoing NAT)
    os.system("nft add chain ip nat postrouting { type nat hook postrouting priority 100 \\; }")

    # DNAT: Matches any traffic aimed at the proxy’s IP on port 5000 
    # Redirects this traffic to the server IP, allowing the proxy to forward requests from the client to the server.
    #os.system(f"nft add rule ip nat prerouting iifname eth0 ip saddr {client_ip} ip daddr {proxy_ip} tcp dport 5000 dnat to {server_ip}")

    # SNAT: Modify source IP for traffic coming from the client to make it appear as though it's coming from the proxy
    #os.system(f"nft add rule ip nat postrouting oifname eth0 ip saddr {client_ip} ip daddr {server_ip} snat to {proxy_ip}")

    # Create an inet filter table for filtering (optional, depending on your filtering needs)
    # os.system("nft add table inet filter")

    # Add input chain to filter traffic (policy drop by default)
    #os.system("nft add chain inet filter input { type filter hook input priority 0 \\; policy drop \\; }")

    # Allow only master to access port 6000 on the gateway
    #os.system(f"nft add rule inet filter input ip saddr {master_ip} tcp dport 6000 accept")

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
    # Setup initial nftables rules
    setup_nftables()

    # Start the TCP server to listen for updates from the master
    start_tcp_server()

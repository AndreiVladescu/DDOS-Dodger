import socket
import random
import socketserver
import threading
from dns_server import ThreadedDNSServer

# Static IP of the Proxy
PROXY_IP = '172.18.0.20'
# The port where the Proxy listens for socket connections
PROXY_PORT = 6000  

# Data structure to keep track of client-server-proxy connections
connection_records = []

# Function to send IP update to the proxy using TCP sockets
def update_proxy(action, client_ip, server_ip):
    try:
        # Create a TCP client socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((PROXY_IP, PROXY_PORT))

            # Send the action and IPs to the Proxy (e.g., "allow 172.18.0.100 172.18.0.30")
            message = f"{action} {client_ip} {server_ip}".encode()
            client_socket.sendall(message)

            # Receive the response from the Proxy
            response = client_socket.recv(1024)
            print(f"Proxy response: {response.decode()}")

    except Exception as e:
        print(f"Error while communicating with Proxy: {e}")

# Function to manage the connection (either allow or deny)
def manage_connection(action, client_ip, server_ip):
    if action == "allow":
        success = update_proxy(action, client_ip, server_ip)

        # If the update is successful, add the connection to the records
        connection_records.append({
            "client_ip": client_ip,
            "proxy_ip": PROXY_IP,
            "server_ip": server_ip
        })

    elif action == "deny":
        # Find and remove the connection record for the client-server pair
        connection_records[:] = [record for record in connection_records 
                                 if not (record['client_ip'] == client_ip and record['server_ip'] == server_ip)]
        # Send deny request to Proxy
        update_proxy(action, client_ip, server_ip)

# Function to load default rules into the proxy at the beginning
def load_default_rules():
    # Static IPs of the client and nest
    client_ip = "172.18.0.100"
    nest_ip = "172.18.0.30"

    # Allow traffic from client to nest by default
    update_proxy("allow", client_ip, nest_ip)

if __name__ == "__main__":
    # Load default rules into the Proxy
    # load_default_rules()

    # Create the DNS server instance
    dns_server = ThreadedDNSServer()

    # Start the DNS server in a separate thread
    dns_server.start()

    # Run the master loop to accept user input
    while True:
        # Prompt for user input
        user_input = input("\nEnter action (allow/deny) client_ip server_ip: ")
        
        # Exit the loop if the user types 'exit'
        if user_input.lower() == 'exit':
            print("Exiting program.")
            break
        
        try:
            # Split input into components
            action, client_ip, server_ip = user_input.split()

            # Validate the action
            if action not in ["allow", "deny"]:
                print("Invalid action. Please use 'allow' or 'deny'.")
                continue

            # Manage the connection based on user input
            manage_connection(action, client_ip, server_ip)

            # Print the updated connection records
            print("\nCurrent Connections:")
            for record in connection_records:
                print(f"Client: {record['client_ip']} -> Proxy: {record['proxy_ip']} -> Server: {record['server_ip']}")
        
        except ValueError:
            print("Invalid input format. Please enter: <action> <client_ip> <server_ip>")
        except Exception as e:
            print(f"An error occurred: {e}")
            dns_server.stop()
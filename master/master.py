import socket
import random
import socketserver
import threading
from dnslib import DNSRecord, QTYPE, RR, A
import json
from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Static IPs of the Proxies
PROXY_IPS = {'172.18.0.21', '172.18.0.22', '172.18.0.23' }
# The port where the Proxy listens for socket connections
PROXY_PORT = 6000  

# Data structure to keep track of client-server-proxy connections
connection_records = []

### DNS Server Communication ###

class CustomDNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        request = DNSRecord.parse(data)

        # Extract the client's IP address
        client_ip = self.client_address[0]
        print(f"Received DNS request from client IP: {client_ip}")

        # Extract the domain name being queried
        domain_name = str(request.q.qname)
        #print(f"Received query for: {domain_name}")

        # Custom logic to determine the response IP
        response_ip = self.get_response_ip(domain_name, client_ip)

        # Build the DNS response
        response = request.reply()
        if response_ip:
            # Add the answer record with the determined IP address
            response.add_answer(RR(domain_name, QTYPE.A, rdata=A(response_ip)))
            #print(f"Responding with IP: {response_ip}")
        else:
            print("No response IP determined; returning NXDOMAIN.")

        # Send the response back to the client
        socket.sendto(response.pack(), self.client_address)

    def get_response_ip(self, domain_name, client_ip):
        # Custom logic for different domains or subdomains
        if "city.iot.gov" in domain_name:
            rc, proxy_ip = manage_connection(action="allow", client_ip=client_ip, nest_ip="172.18.0.30")
            if rc != -1 :
                return proxy_ip
            else:
                return "0.0.0.0"
        else:
            return "0.0.0.0"  # Define fallback IP, or None for NXDOMAIN


class ThreadedDNSServer:
    def __init__(self, host="0.0.0.0", port=53):
        self.server = socketserver.UDPServer((host, port), CustomDNSHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True  # Daemonize thread to exit when the main program ends

    def start(self):
        print("Starting DNS server in a separate thread...")
        self.thread.start()

    def stop(self):
        print("Stopping DNS server...")
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

### Web Application ###

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/connections')
def get_connections():
    return jsonify(connection_records)

def web_app():
    app.run(debug=True, use_reloader=False, port=8080, host='0.0.0.0')

### Proxy Server Communication ###

# Function to send IP update to the proxy using TCP sockets
def update_proxy(action, client_ip, server_ip, proxy_ip):
    try:
        # Create a TCP client socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((proxy_ip, PROXY_PORT))

            # Send the action and IPs to the Proxy (e.g., "allow 172.18.0.100 172.18.0.30")
            message = f"{action} {client_ip} {server_ip}".encode()
            client_socket.sendall(message)

            # Receive the response from the Proxy
            response = client_socket.recv(1024).decode()
            print(f"Proxy response: {response}")
            if "IP pair allowed" in response:
                return 1
            else:
                return 0
    except Exception as e:
        print(f"Error while communicating with Proxy: {e}")
        return -1

# Function to manage the connection (either allow or deny)
def manage_connection(action, client_ip, nest_ip):
    random_proxy_ip = random.choice(list(PROXY_IPS))

    if action == "allow":
        is_client_ip_present = any(record["client_ip"] == 
                                   client_ip for record in connection_records)
        if is_client_ip_present:
            print(f"Client IP {client_ip} is already in the records.")
            proxy_ip = next((record["proxy_ip"] for record in connection_records if record["client_ip"] == client_ip), None)
            return 0, proxy_ip

        rc = update_proxy(action, client_ip, nest_ip, random_proxy_ip)
        if rc == -1:
            print("Error updating proxy. Aborting.")
            return -1
        elif rc == 0:
            print("IP pair already allowed. Updating it to our connection.")
        elif rc == 1:
            print("IP pair allowed successfully.")
            
        # If the update is error-free, add the connection to the records
        connection_records.append({
            "client_ip": client_ip,
            "proxy_ip": random_proxy_ip,
            "nest_ip": nest_ip
        })

        return 1, random_proxy_ip

    elif action == "deny":
        # Find and remove the connection record for the client-nest pair
        connection_records[:] = [record for record in connection_records 
                                 if not (record['client_ip'] == client_ip and record['nest_ip'] == nest_ip)]
        # Send deny request to Proxy
        rc = update_proxy(action, client_ip, nest_ip, record['proxy_ip'])
    
    return 1


if __name__ == "__main__":
    
    
    dns_server = ThreadedDNSServer()
    dns_server.start()

    threading.Thread(target=web_app).start()

    # Run the master loop to accept user input
    while True:
        # Prompt for user input
        user_input = input("\nEnter action (allow/deny) client_ip nest_ip: ")
        
        # Exit the loop if the user types 'exit'
        if user_input.lower() == 'exit':
            print("Exiting program.")
            break
        
        try:
            # Split input into components
            action, client_ip, nest_ip = user_input.split()

            # Validate the action
            if action not in ["allow", "deny"]:
                print("Invalid action. Please use 'allow' or 'deny'.")
                continue

            # Manage the connection based on user input
            manage_connection(action, client_ip, nest_ip)

            # Print the updated connection records
            print("\nCurrent Connections:")
            for record in connection_records:
                print(f"Client: {record['client_ip']} -> Proxy: {record['proxy_ip']} -> Nest: {record['nest_ip']}")
        
        except ValueError:
            print("Invalid input format. Please enter: (allow/deny) <client_ip> <nest_ip>")
        except Exception as e:
            print(f"An error occurred: {e}")
            dns_server.stop()
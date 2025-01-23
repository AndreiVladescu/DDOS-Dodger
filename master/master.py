import socket
import random
import socketserver
import threading
from dnslib import DNSRecord, QTYPE, RR, A
import json
from flask import Flask, render_template, jsonify
import paho.mqtt.client as mqtt
from time import sleep

app = Flask(__name__)

# Static IPs of the Proxies
PROXY_IPS = {'172.18.0.21', '172.18.0.22', '172.18.0.23' }
# The port where the Proxy listens for socket connections
PROXY_PORT = 6000  

# Data structure to keep track of client-server-proxy connections
connection_records = []

# MQTT Broker details
MQTT_BROKER = "172.18.0.60"
MQTT_PORT = 1883
MQTT_TOPIC_COMMAND = "proxy/command"
MQTT_TOPIC_RESPONSE = "proxy/response"

# Data structure to keep track of client-server-proxy connections
connection_records = []

# MQTT client
mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)

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
        print(f"Received query for: {domain_name}")

        # Custom logic to determine the response IP
        response_ip = self.get_response_ip(domain_name, client_ip)

        # Build the DNS response
        response = request.reply()
        if response_ip:
            # Add the answer record with the determined IP address
            response.add_answer(RR(domain_name, QTYPE.A, rdata=A(response_ip)))
            print(f"Responding with IP: {response_ip}")
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

def on_connect(client, userdata, flags, rc, properties):
    if rc == 0:
        print("Connected to MQTT broker.")
        # Subscribe to the response topic
        client.subscribe(MQTT_TOPIC_RESPONSE)
    else:
        print(f"Failed to connect, return code {rc}")

def on_message(client, userdata, msg):
    try:
        # Parse incoming MQTT messages
        payload = json.loads(msg.payload.decode())
        if msg.topic == MQTT_TOPIC_RESPONSE:
            print(f"Response received: {payload}")
            handle_proxy_response(payload)
    except Exception as e:
        print(f"Error processing message: {e}")

def handle_proxy_response(response):
    # Handle responses from proxies, e.g., updating connection records
    client_ip = response.get("client_ip")
    action = response.get("action")
    nest_ip = response.get("nest_ip")
    print(f"Proxy {response.get('proxy_ip')} reports {action} for {client_ip} while accessing {nest_ip}")
    # Make a switch case for different actions
    print(f"Revoking access for client {client_ip}")
    manage_connection("deny", client_ip, nest_ip)

# Function to manage the connection (either allow or deny)
def manage_connection(action, client_ip, nest_ip):
    # Check if the action is valid
    if action not in ["allow", "deny"]:
        raise ValueError("Invalid action. Must be 'allow' or 'deny'.")

    # Check if the client_ip is already recorded
    existing_record = next((record for record in connection_records if record["client_ip"] == client_ip and record["nest_ip"] == nest_ip), None)

    if action == "allow":
        if existing_record:
            print(f"Connection already exists: {existing_record}")
            return -1

        # Pick a random proxy IP from the list of available proxies
        proxy_ip = random.choice(list(PROXY_IPS))

        # Add the new connection to the records
        connection_records.append({
            "client_ip": client_ip,
            "proxy_ip": proxy_ip,
            "nest_ip": nest_ip
        })

        # Publish the 'allow' command to the selected proxy
        message = {
            "action": "allow",
            "client_ip": client_ip,
            "nest_ip": nest_ip,
            "proxy_ip": proxy_ip
        }
        mqtt_client.publish(MQTT_TOPIC_COMMAND, json.dumps(message))
        print(f"Published 'allow' command to {proxy_ip} for {client_ip} -> {nest_ip}")

        return 0, proxy_ip
    
    elif action == "deny":
        if not existing_record:
            print(f"No existing connection for {client_ip} -> {nest_ip}. Nothing to deny.")
            return -1

        proxy_ip = existing_record["proxy_ip"]

        # Remove the connection from the records
        connection_records.remove(existing_record)

        # Publish the 'deny' command to the appropriate proxy
        message = {
            "action": "deny",
            "client_ip": client_ip,
            "nest_ip": nest_ip,
            "proxy_ip": proxy_ip
        }
        mqtt_client.publish(MQTT_TOPIC_COMMAND, json.dumps(message))
        print(f"Published 'deny' command to {proxy_ip} for {client_ip} -> {nest_ip}")


def setup_mqtt():
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    mqtt_client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    mqtt_client.loop_start()

if __name__ == "__main__":
    sleep(5)
    
    dns_server = ThreadedDNSServer()
    dns_server.start()

    threading.Thread(target=web_app).start()

    setup_mqtt()

    while True:
        user_input = input("\nEnter action (allow/deny) client_ip nest_ip: ")
        
        if user_input.lower() == 'exit':
            print("Exiting program.")
            break
        
        try:
            action, client_ip, nest_ip = user_input.split()

            if action not in ["allow", "deny"]:
                print("Invalid action. Please use 'allow' or 'deny'.")
                continue

            # Manage the connection based on user input
            manage_connection(action, client_ip, nest_ip)

            print("\nCurrent Connections:")
            for record in connection_records:
                print(f"Client: {record['client_ip']} -> Proxy: {record['proxy_ip']} -> Nest: {record['nest_ip']}")
        
        except ValueError:
            print("Invalid input format. Please enter: (allow/deny) <client_ip> <nest_ip>")
        except Exception as e:
            print(f"An error occurred: {e}")
            dns_server.stop()
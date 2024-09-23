import requests
import json
import random  # Import random to pick a random proxy

# List of proxy nodes (their URLs)
PROXY_NODES = [
    "http://192.168.10.10:5000/update-pairs",
    "http://192.168.10.20:5000/update-pairs",
    "http://192.168.10.30:5000/update-pairs"
]

# Data structure to keep track of client-server-proxy connections
connection_records = []

def update_proxy(action, client_ip, proxy_ip, server_ip):
    # Data payload to be sent to the proxy
    data = {
        "action": action,
        "source_ip": client_ip,
        "dest_ip": server_ip
    }

    try:
        # Send the update request to the specified proxy
        print(f"Sending update to proxy: {proxy_ip}")
        response = requests.post(proxy_ip, json=data)

        # Handle the response from the proxy node
        if response.status_code == 200:
            result = response.json()
            print(f"Update successful on {proxy_ip}: {result}")
            return True
        else:
            print(f"Failed to update proxy {proxy_ip}: {response.status_code}, {response.text}")
            return False

    except Exception as e:
        print(f"Error while connecting to proxy {proxy_ip}: {e}")
        return False

def manage_connection(action, client_ip, server_ip):
    if action == "allow":
        # Pick one random proxy from the list
        chosen_proxy = random.choice(PROXY_NODES)
        success = update_proxy(action, client_ip, chosen_proxy, server_ip)
        
        if success:
            # Add the connection to the records
            connection_records.append({
                "client_ip": client_ip,
                "proxy_ip": chosen_proxy,
                "server_ip": server_ip
            })

    elif action == "deny":
        # Find and remove the connection record for the client-server pair
        connection_records[:] = [record for record in connection_records 
                                 if not (record['client_ip'] == client_ip and record['server_ip'] == server_ip)]

        # Deny on the proxy that was previously facilitating this connection
        for record in connection_records:
            if record['client_ip'] == client_ip and record['server_ip'] == server_ip:
                chosen_proxy = record['proxy_ip']
                update_proxy(action, client_ip, chosen_proxy, server_ip)
                break

if __name__ == "__main__":

    while True:
        # Prompt for user input
        user_input = input("\nEnter action (allow/deny) client_ip server_ip: ")
        
        # Exit the loop if user types 'exit'
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

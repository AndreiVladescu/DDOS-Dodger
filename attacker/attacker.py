import time
import requests
from dnslib import DNSRecord
import socket

proxy_url = None
proxy_ip = None

def query_dns_server(domain, server_ip, port=53):
    # Construct a DNS query packet
    dns_query = DNSRecord.question(domain)

    # Send the DNS query to the server
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)  # Set a timeout for the response
        sock.sendto(dns_query.pack(), (server_ip, port))

        # Receive the response from the server
        try:
            data, _ = sock.recvfrom(512)  # 512 bytes is typical for DNS responses
            dns_response = DNSRecord.parse(data)

            # Print the answers section of the DNS response
            for answer in dns_response.rr:
                return answer.rdata  # Return the IP address found in the response
        except socket.timeout:
            print("Request timed out.")
            return None


def send_request():
    global proxy_ip
    global proxy_url

    print("Starting the attacker...")
    while True:

        try:
            # Query the DNS server for the Proxy's IP address
            proxy_ip = query_dns_server("city.iot.gov", "172.18.0.10", 53)
            print(f"Server IP address received from DNS: {proxy_ip}")
            proxy_url = f"http://{proxy_ip}:80/"
        except Exception as e:
            print(f"Error querying DNS server: {e}")
            continue
        while True:
            if proxy_ip is None:
                break
            try:
                # Make a GET request to the Proxy
                response = requests.get(proxy_url, timeout=5)
                print(f"Response from Proxy: {response.status_code} - {response.text}")
            except requests.exceptions.RequestException as e:
                print(f"Error connecting to Proxy: {e}")
                break
                
            print('Cycle completed')
            # Wait for 1 second before making the next request
            time.sleep(1)
        time.sleep(1)
        
if __name__ == "__main__":
    send_request()

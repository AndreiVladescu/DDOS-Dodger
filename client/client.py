import time
import requests

proxy_url = "http://172.18.0.20:5000/"  # Use the Proxy container name as its DNS

def send_request():
    print("Starting the client...")
    while True:
        try:
            # Make a GET request to the Proxy
            response = requests.get(proxy_url, timeout=5)
            print(f"Response from Proxy: {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to Proxy: {e}")
        
        print('Cycle completed')
        # Wait for 5 seconds before making the next request
        time.sleep(5)

if __name__ == "__main__":
    send_request()

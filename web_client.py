import time
import requests

def fetch():
    while True:
        try:
            response = requests.get("http://10.0.0.1:8000")
            print(response.text)
            time.sleep(5)  # Wait for 5 seconds before the next request
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
            print("Could not connect to the server. Trying again in 3 seconds...")
            time.sleep(3)  # Wait for 3 seconds before trying again

if __name__ == "__main__":
    fetch()

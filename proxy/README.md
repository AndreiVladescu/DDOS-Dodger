
## Plan

 - The Python script will run a Flask API that listens for POST requests from the master node.
 - When the master node sends a request, the script will update the iptables rules accordingly (allow or deny IP pairs).
 - The initial hardcoded pairs will remain, and the master node can modify or add to these rules.

## Example Master Node Request


``curl -X POST http://<your-server-ip>:5000/update-pairs -H "Content-Type: application/json" \
    -d '{"action": "allow", "source_ip": "192.168.0.101", "dest_ip": "172.16.0.101"}'``

``curl -X POST http://<your-server-ip>:5000/update-pairs -H "Content-Type: application/json" \
    -d '{"action": "deny", "source_ip": "192.168.0.100", "dest_ip": "172.16.0.100"}'``

## Running the Script

 1. Run the Python script with `sudo` since it modifies `iptables`:
 ``sudo python3 iptables_forwarder.py``
 2. The Flask API will start listening on `http://0.0.0.0:5000`.
 3. You can now send requests from the master node to update IP pairs dynamically.


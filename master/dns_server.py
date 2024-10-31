from dnslib import DNSRecord, QTYPE, RR, A
import socketserver
import threading

class CustomDNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, socket = self.request
        request = DNSRecord.parse(data)

        # Extract the domain name being queried
        domain_name = str(request.q.qname)
        #print(f"Received query for: {domain_name}")

        # Custom logic to determine the response IP
        response_ip = self.get_response_ip(domain_name)

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

    def get_response_ip(self, domain_name):
        # Custom logic for different domains or subdomains
        if "city.iot.gov" in domain_name:
            return "172.18.0.20"  # Define your custom IP here
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
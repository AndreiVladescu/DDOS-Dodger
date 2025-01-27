import os
import time

def configure_container_routing(container_interface, target_server_ip):
    try:
        # Enable IP forwarding
        os.system("sysctl -w net.ipv4.ip_forward=1")

        # Allow traffic forwarding through the container
        os.system(f"iptables -A FORWARD -i {container_interface} -j ACCEPT")

        # Add DNAT rule to forward traffic to the target server
        os.system(f"iptables -t nat -A PREROUTING -i {container_interface} -j DNAT --to-destination {target_server_ip}")

        # Add masquerading for outgoing traffic
        os.system("iptables -t nat -A POSTROUTING -j MASQUERADE")

        print("[INFO] Routing and NAT rules successfully configured.")
    except Exception as e:
        print(f"[ERROR] Failed to configure routing: {e}")

def run_indefinitely():
    print("[INFO] Application is running. Press Ctrl+C to stop.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[INFO] Application stopped.")

if __name__ == "__main__":
    # Define the container's network interface and target server IP
    container_interface = "eth0"  # Replace with the actual container's network interface
    target_server_ip = "192.168.0.90"  # Replace with the target server's IP address

    # Configure routing and NAT
    configure_container_routing(container_interface, target_server_ip)

    # Keep the application running indefinitely
    run_indefinitely()

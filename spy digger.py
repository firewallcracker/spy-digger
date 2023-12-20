import socket
import sys
import concurrent.futures
import subprocess
import requests
from queue import Queue
import requests

def get_user_input():
    target = input("Enter the target host (e.g., example.com): ") or "localhost"
    start_port = int(input("Enter the starting port (default is 1): ") or 1)
    end_port = int(input("Enter the ending port (default is 100): ") or 100)
    return target, start_port, end_port

def scan_port(port, result_queue):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)  # Set a timeout for the connection attempt
        result = s.connect_ex((target, port))
        if result == 0:
            result_queue.put(port)
            print(f"Port {port} is OPEN")

def detect_os():
    try:
        # Perform OS detection scan here
        result = subprocess.check_output(["nmap", "-O", target], text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error during OS detection: {e}")



def check_web_vulnerability(port):
    url = f"http://{target}:{port}"
    try:
        response = requests.get(url, timeout=5)  # Adjust timeout as needed
        if response.status_code == 200:
            print(f"Potential vulnerability found on {url}")
    except requests.exceptions.RequestException:
        pass

def scan_service_version(port):
    try:
        # Perform service version scan here
        result = subprocess.run(["nmap", "-p", str(port), "-sV", target], capture_output=True, text=True, check=True)
        print(f"Service version scan results for port {port}:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error during service version scan: {e}")


def connect_to_vpn(vpn_url, vpn_username, vpn_password):
    try:
        # Use requests library to connect to the VPN
        response = requests.post(vpn_url, auth=(vpn_username, vpn_password))
        response.raise_for_status()
        print("Connected to VPN successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to VPN: {e}")
        sys.exit()

if __name__ == "__main__":
    print("                  ☻       ☻        ☻          ☻☻☻      ☻   ☻     |  |                  ")
    print("                  ☻       ☻       ☻ ☻       ☻          ☻  ☻      |  |                 ")
    print("                  ☻☻☻☻☻☻☻☻☻      ☻☻☻☻☻      ☻          ☻ ☻       |  |             ")
    print("                  ☻       ☻     ☻     ☻     ☻          ☻  ☻      |  |          ")
    print("                  ☻       ☻    ☻       ☻     ☻☻☻       ☻   ☻     .  .          ")
    print("Welcome to the Port Scanner!")

    target, start_port, end_port = get_user_input()

    vpn_url = input("Enter your VPN service URL (e.g., https://vpn-provider.com): ")
    vpn_username = input("Enter your VPN username: ")
    vpn_password = input("Enter your VPN password: ")

    # Connect to VPN
    connect_to_vpn(vpn_url, vpn_username, vpn_password)

    print(f"\nScanning target {target} on ports {start_port}-{end_port}...\n")

    open_ports = Queue()

    while True:
        print("\nChoose an option:")
        print("1. Scan for open ports")
        print("2. Detect the operating system")
        print("3. Scan for vulunerbility")
        print("4. Scan service versions")
        print("5. Disconnect from VPN and Exit")

        try:
            choice = int(input("Enter your choice (1-4): "))

            if choice == 1:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    executor.map(scan_port, range(start_port, end_port + 1), [open_ports] * (end_port - start_port + 1))
            elif choice == 2:
                detect_os()

            elif choice == 3:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    executor.map(check_web_vulnerability, list(open_ports.queue))
            elif choice == 4:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    executor.map(scan_service_version, list(open_ports.queue))
            elif choice == 5:
                print("Disconnecting from VPN.")
                # Add VPN disconnect logic if needed
                sys.exit()
            else:
                print("Invalid option. Please choose a valid option.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nUser interrupted. Exiting.")
            sys.exit()

    if not open_ports.empty():
        print("\nOpen ports:", list(open_ports.queue))
    else:
        print("\nNo open ports found.")

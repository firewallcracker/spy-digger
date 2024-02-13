import socket
import json
import getpass
import sys
import concurrent.futures
import subprocess
import requests
from queue import Queue
import requests
from reportlab.pdfgen import canvas
import time
import random
from zapv2 import ZAPv2
import spacy



def print_frame(frame):
    print(frame)
    time.sleep(0.5)  # Adjust the delay time as needed

def generate_random_ascii_art():
    ascii_art_styles = [
        """
   ____                  _    _______ _     _             
  |  _ \ ___  __ _ _ __| | _|__   __| |   (_)            
  | |_) / _ \/ _` | '__| |/ /  | |  | |__  _ _ __   __ _ 
  |  __/  __/ (_| | |  |   <   | |  | '_ \| | '_ \ / _` |
  |_|   \___|\__,_|_|  |_|\_\  |_|  |_.__/|_|_| |_|\__, |
                                                     __/ |
                                                    |___/ 
        """
        # Add more ASCII art styles as needed
    ]

    return random.choice(ascii_art_styles)

def print_animated_name():
    for _ in range(5):  # Adjust the number of frames as needed
        frame = generate_random_ascii_art()
        print_frame(frame)

    
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
        else:
            print(f"Port {port} is CLOSED")

def detect_os():
    try:
        # Perform OS detection scan here
        result = subprocess.check_output(["nmap", "-O", target], text=True)
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error during OS detection: {e}")



def nmap_web_vulnerability_scan(target, port):
    try:
        # Perform Nmap web vulnerability scan
        result = subprocess.check_output(["nmap", "--script", "http-vuln*", "-p", str(port), target], text=True)
        print("Nmap Web Vulnerability Scan Results:")
        print(result)
        return result  # Return the result for further processing if needed
    except subprocess.CalledProcessError as e:
        print(f"Error during Nmap web vulnerability scan: {e}")
        return None

def check_web_vulnerability(port):
    url = f"http://{target}:{port}"
    try:
        response = requests.get(url, timeout=5)  # Adjust timeout as needed
        if response.status_code == 200:
            print(f"Potential vulnerability found on {url}")
            # Integrate Nmap web vulnerability scan
            nmap_result = nmap_web_vulnerability_scan(target, port)
            if nmap_result:
                # Further processing based on Nmap result
                pass
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
    while True:
        try:
            # Use requests library to connect to the VPN
            response = requests.post(vpn_url, auth=(vpn_username, vpn_password))
            response.raise_for_status()
            print("Connected to VPN successfully.")
            break  # Break out of the loop if connection is successful
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to VPN: {e}")
            retry = input("Do you want to retry connecting to VPN? (yes/no): ").lower()
            if retry != 'yes':
                print("Exiting.")
                sys.exit()



def save_credentials(vpn_url, username, password):
    credentials = {"vpn_url": vpn_url, "username": username, "password": password}
    with open("credentials.json", "w") as file:
        json.dump(credentials, file)
    print("Credentials saved successfully.")

def load_credentials():
    try:
        with open("credentials.json", "r") as file:
            credentials = json.load(file)
            return credentials.get("vpn_url"), credentials.get("username"), credentials.get("password")
    except FileNotFoundError:
        return None, None, None


def extract_information_from_nmap_output(nmap_output):
    nlp = spacy.load("en_core_web_sm")
    doc = nlp(nmap_output)
    entities = [ent.text for ent in doc.ents]
    return entities



def run_zap_scan(target_url):
    # Create a ZAP instance
    zap = ZAPv2()

    try:
        # Access the target URL through the ZAP proxy
        print(f"Accessing {target_url} through ZAP proxy...")
        zap_access_result = zap.urlopen(target_url)
        print("Access result:", zap_access_result)

        # Perform the spider scan
        print("Starting ZAP spider scan...")
        scan_id = zap.spider.scan(target_url)
        print("Spider scan ID:", scan_id)

        # Wait for the spider scan to complete
        print("Waiting for spider scan to complete...")
        while True:
            if zap.spider.status(scan_id) == '100':
                break
            time.sleep(2)

        # Print the spider scan results
        print("Spider scan complete. Results:")
        spider_results = zap.spider.results(scan_id)
        print(spider_results)

        # ... (rest of your Zap scan logic)
    except Exception as e:
        print(f"Error during Zap scan: {e}")





def generate_pdf_report_ai(entities):
    pdf_filename = "scanning_report_ai.pdf"
    pdf = canvas.Canvas(pdf_filename)

    pdf.setFont("Helvetica", 12)
    pdf.drawString(100, 800, "AI-Generated Scanning Report")

    pdf.drawString(50, 780, "Extracted Information:")

    for idx, entity in enumerate(entities, start=1):
        pdf.drawString(70, 760 - idx * 20, f"{entity}")

    # Add Zap scan details to the report
    pdf.drawString(50, 720, "Zap Scan Details:")
    pdf.drawString(70, 700, "Zap scan performed on:")
    pdf.drawString(150, 700, f"http://{target}")

    pdf.save()
    print(f"AI-Generated scanning report saved as {pdf_filename}")
    




os_detection_result = None
vulnerabilities_found = []
service_version_results = []



if __name__ == "__main__":
    print_animated_name()
    print("Welcome to the Port Scanner!")

    target, start_port, end_port = get_user_input()

    saved_vpn_url, saved_username, saved_password = load_credentials()

    if saved_vpn_url and saved_username and saved_password:
        print(f"Saved credentials found: VPN URL: {saved_vpn_url}, Username: {saved_username}")
        use_saved_credentials = input("Do you want to use these credentials? (yes/no): ").lower()
        if use_saved_credentials == "yes":
            vpn_url = saved_vpn_url
            vpn_username = saved_username
            vpn_password = saved_password
        else:
            vpn_url = input("Enter your VPN service URL (e.g., https://vpn-provider.com): ")
            vpn_username = input("Enter your VPN username: ")
            vpn_password = getpass.getpass("Enter your VPN password: ")
            save_credentials(vpn_url, vpn_username, vpn_password)
    else:
        vpn_url = input("Enter your VPN service URL (e.g., https://vpn-provider.com): ")
        vpn_username = input("Enter your VPN username: ")
        vpn_password = getpass.getpass("Enter your VPN password: ")
        save_credentials(vpn_url, vpn_username, vpn_password)

    connect_to_vpn(vpn_url, vpn_username, vpn_password)

    print(f"\nScanning target {target} on ports {start_port}-{end_port}...\n")

    open_ports = Queue()
    while True:
        print("\nChoose an option:")
        print("1. Scan for open ports")
        print("2. Detect the operating system")
        print("3. Scan for vulnerability")
        print("4. Scan service versions")
        print("5. Get full scanning result")
        print("6. Disconnect from VPN and Exit")
        print("7. Full Scan")
        print("8. Generate AI-aided PDF report")

        try:
            choice = int(input("Enter your choice (1-8): "))

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
                generate_pdf_report(list(open_ports.queue), os_detection_result, vulnerabilities_found, service_version_results)
            elif choice == 6:
                print("Disconnecting from VPN.")
                sys.exit()
            elif choice == 7:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    executor.map(scan_port, range(start_port, end_port + 1), [open_ports] * (end_port - start_port + 1))
                    os_detection_result = detect_os()
                    executor.map(check_web_vulnerability, list(open_ports.queue))
                    executor.map(scan_service_version, list(open_ports.queue))
            elif choice == 8:
    # Generate AI-aided PDF report
              nmap_output = subprocess.check_output(["nmap", target], text=True)
              extracted_information = extract_information_from_nmap_output(nmap_output)
              generate_pdf_report_ai(extracted_information)

    # Run Zap scan
              target_url = f"http://{target}"
              run_zap_scan(target_url)
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

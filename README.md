# spy-digger

## Overview

Welcome to the spy-digger! This Python script is designed to help users scan and analyze networks for open ports, detect operating systems, check for web vulnerabilities, and scan service versions. It provides a versatile and interactive interface for users to perform various network-related tasks.

## Features

- **Port Scanning:** Quickly identify open ports on a target host within a specified port range.
- **Operating System Detection:** Utilize Nmap to perform an operating system detection scan on the target host.
- **Web Vulnerability Scan:** Check for potential vulnerabilities on open ports by accessing them via HTTP.
- **Service Version Scanning:** Use Nmap to scan and identify the versions of services running on open ports.
- **VPN Integration:** Connect to a VPN service before initiating scans for enhanced security.

## Getting Started

1. **Installation:**
   - Ensure Python is installed on your system (version 3.6 or higher).
   - Install the required dependencies: `requests` (`pip install requests`).

2. **Usage:**
   - Run the script in your terminal or command prompt: `python port_scanner.py`.
   - Follow the prompts to enter the target host, port range, and VPN credentials.

3. **Options:**
   - Choose from various options in the menu to perform specific tasks:
     - Scan for open ports
     - Detect the operating system
     - Scan for web vulnerabilities
     - Scan service versions
     - Disconnect from VPN and exit

4. **Results:**
   - View the results of each scan in real-time as the script progresses.

## Notes

- Ensure Nmap is installed on your system for accurate operating system detection and service version scanning.
- Web vulnerability scanning assumes potential vulnerabilities are accessible via HTTP on open ports.

## Disclaimer

This tool is intended for educational and ethical use only. Unauthorized scanning of networks and systems without proper authorization is illegal and against ethical standards. Use this tool responsibly and only on networks and systems for which you have explicit permission.

## Author

[Piyush Kumar]

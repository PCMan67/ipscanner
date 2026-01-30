# grab all devices connected to the network and show the private IP addresses, MAC addresses, and manufacturers, and only windows compatible.
import ctypes
import subprocess
import platform
import re
import os
import sys


def get_ip_range():
    try:
        hostname = subprocess.check_output(
            "hostname", shell=True, timeout=5).decode().strip()
        local_ip = subprocess.check_output(
            f"ping -4 -n 1 {hostname}", shell=True, timeout=10).decode()
        ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', local_ip)
        if ip_match:
            ip_address = ip_match.group(0)
            subnet = '.'.join(ip_address.split('.')[:-1]) + '.0/24'
            return subnet
        else:
            print("Could not determine local IP address.")
            sys.exit(1)
    except subprocess.TimeoutExpired:
        print("Command timed out while getting IP range.")
        sys.exit(1)
    except Exception as e:
        print(f"Error getting IP range: {e}")
        sys.exit(1)


def scan_network(ip_range):
    """Scan network using Windows arp command instead of scapy."""
    clients = []
    try:
        # Use Windows arp command to get ARP table
        result = subprocess.check_output("arp -a", shell=True).decode()
        for line in result.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                # Filter for dynamic entries (not static)
                if len(parts) >= 3 and parts[2] == "dynamic":
                    ip = parts[0]
                    mac = parts[1]
                    if re.match(r'(\d{1,3}\.){3}\d{1,3}', ip):
                        client_dict = {"ip": ip, "mac": mac}
                        clients.append(client_dict)
    except Exception as e:
        print(f"Error scanning network: {e}")
    return clients


def get_manufacturer(mac_address):
    try:
        with open("manuf.txt", "r") as f:
            for line in f:
                if mac_address.upper().startswith(line.split()[0]):
                    return ' '.join(line.split()[1:])
    except FileNotFoundError:
        print("Manufacturer file not found.")
    return "Unknown"


def display_clients(clients):
    print("IP Address\t\tMAC Address\t\tManufacturer")
    print("--------------------------------------------------------------")
    for client in clients:
        manufacturer = get_manufacturer(client["mac"])
        print(f"{client['ip']}\t{client['mac']}\t{manufacturer}")


def check_admin():
    """Check if running with admin privileges."""
    if os.name == 'nt':
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("Warning: This script works better with admin privileges.")
        except:
            pass
    else:
        if os.geteuid() != 0:
            print("Warning: This script requires root privileges for best results.")


if __name__ == "__main__":
    check_admin()
    ip_range = get_ip_range()
    print(f"Scanning IP range: {ip_range}")
    clients = scan_network(ip_range)
    print(f"Found {len(clients)} device(s)")
    display_clients(clients)

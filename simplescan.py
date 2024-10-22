

from scapy.all import *

# Define a list of common ports that we want to scan on the target host.
ports = [25, 80, 53, 443, 445, 8080, 8443]

# This function performs a SYN scan to check which ports are open on the target host.
# SYN scans are used because they are fast and less intrusive, sending only the initial SYN packet of the TCP handshake.
def SynScan(host):
        # Sending SYN packets to each of the specified ports and waiting for a response.
        # IP(dst=host) creates an IP packet directed to the host.
        # TCP(sport=5555, dport=ports, flags="S") sends a TCP SYN packet (flags="S") from source port 5555 to the target ports.
        ans, unans = sr(IP(dst=host)/TCP(sport=5555, dport=ports, flags="S"), timeout=2, verbose=0)
        
        # Print the IP of the host we're scanning to indicate which host we are checking for open ports.
        print(" Open Ports: %s" % host)
        
        # Loop through all the answered packets (ans), checking if the SYN-ACK response was received,
        # which indicates that the port is open.
        for (s, r) in ans:
                # If the destination port matches the source port in the response, the port is open.
                if s[TCP].dport == r[TCP].sport:
                        print(s[TCP].dport)  # Print the open port number.

# This function performs a DNS scan by sending a DNS query to the target host's port 53 (the default DNS port).
# DNS scans help verify if the target is a DNS server.
def DnsScan(host):
        # Send a UDP packet with a DNS query asking for the domain "google.com".
        ans, unans = sr(IP(dst=host)/UDP(sport=5555, dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com")), timeout=2, verbose=0)
        
        # If we get a response, it means the host is likely a DNS server (it responded to the DNS query).
        if ans:
                print("DNS SERVER AT %s" % host)

# Define the host (Google's public DNS server in this case) we want to scan.
host = "8.8.8.8"

# Perform a SYN scan to detect open ports on the target.
SynScan(host)

# Perform a DNS scan to check if the target is functioning as a DNS server.
DnsScan(host)


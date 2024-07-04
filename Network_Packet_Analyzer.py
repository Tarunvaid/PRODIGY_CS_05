from scapy.all import sniff, IP, TCP, UDP, conf
import logging

# Set up logging
logging.basicConfig(filename="packet_log.txt", level=logging.INFO, format="%(asctime)s %(message)s")

# Function to process captured packets
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        payload = packet[IP].payload

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            proto = "Other"
            sport = None
            dport = None

        log_message = (
            f"\n[+] Packet Captured:\n"
            f"    Protocol: {proto}\n"
            f"    Source: {ip_src}:{sport}\n"
            f"    Destination: {ip_dst}:{dport}\n"
            f"    Payload: {payload}"
        )

        print(log_message)
        logging.info(log_message)

# Use the Npcap driver
conf.use_pcap = True

# Filter to capture only IP packets
packet_filter = "ip"

# Start sniffing packets
print("Starting packet capture...")
sniff(filter=packet_filter, prn=packet_callback, store=0)

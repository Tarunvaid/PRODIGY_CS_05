###  Network Packet Analyzer 

The provided Python script is a basic network packet analyzer that captures and analyzes network packets. It leverages the Scapy library to sniff packets and logs relevant information such as source and destination IP addresses, protocols, and payload data. The captured packet information is displayed on the console and logged to a file named `packet_log.txt`.

#### Script Breakdown

1. **Imports**:
   - **Scapy**:
     ```python
     from scapy.all import sniff, IP, TCP, UDP, Ether
     ```
     This line imports essential classes and functions from the Scapy library, which is used for network packet manipulation and analysis.
   - **Logging**:
     ```python
     import logging
     ```
     The logging module is used to log captured packet data to a file for persistent storage and analysis.

2. **Setup Logging**:
   ```python
   logging.basicConfig(filename="packet_log.txt", level=logging.INFO, format="%(asctime)s %(message)s")
   ```
   - **Filename**: The log messages will be saved to `packet_log.txt`.
   - **Level**: The logging level is set to `INFO`, meaning all INFO level messages and above will be logged.
   - **Format**: The log format includes a timestamp and the message.

3. **Packet Callback Function**:
   ```python
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
   ```
   - **Function**: `packet_callback(packet)` is called for each captured packet.
   - **Check for IP Layer**: The function checks if the packet contains an IP layer using `if IP in packet`.
   - **Extract Information**:
     - **IP Addresses**: Extracts the source and destination IP addresses.
     - **Payload**: Extracts the payload of the IP packet.
     - **Protocol and Ports**: Determines if the packet is TCP or UDP and extracts the source and destination ports.
   - **Log Message**: Constructs a log message with the packet details.
   - **Output**: Prints the log message to the console and logs it to `packet_log.txt`.

4. **Packet Filter**:
   ```python
   packet_filter = "ip"
   ```
   - **Filter**: The filter is set to capture only IP packets. This is a BPF (Berkeley Packet Filter) filter string.

5. **Start Sniffing**:
   ```python
   print("Starting packet capture...")
   sniff(filter=packet_filter, prn=packet_callback, store=0)
   ```
   - **Message**: Prints a message to the console indicating that packet capture is starting.
   - **Sniff Function**:
     - **Filter**: Uses the specified filter to capture only IP packets.
     - **Callback**: Calls `packet_callback` for each captured packet.
     - **Store**: Setting `store=0` ensures that the packets are not stored in memory, reducing memory usage.

### How to Run the Packet Analyzer Script

1. **Install Dependencies**:
   - **Python**: Ensure Python is installed on your system.
   - **Scapy**: Install Scapy using pip:
     ```bash
     pip install scapy
     ```

2. **Install Npcap**:
   - **Npcap**: Download and install Npcap from the [Npcap website](https://nmap.org/npcap/).
   - During installation, check "Install Npcap in WinPcap API-compatible Mode".

3. **Save the Script**:
   - Save the provided script to a file, e.g., `packet_analyzer.py`.

4. **Run the Script with Administrative Privileges**:
   - **Command Prompt/Terminal**: Open a command prompt or terminal with administrative privileges (right-click and select "Run as administrator").
   - **Navigate**: Navigate to the directory where the script is saved.
   - **Run**: Run the script:
     ```bash
     python packet_analyzer.py
     ```

### Example Usage

When you run the script, it will start capturing packets and display their details on the console. The captured packet details will also be logged to `packet_log.txt`. The script will capture packets until you stop it manually (e.g., by pressing Ctrl+C).

### Summary

This network packet analyzer script captures and logs network packets, providing valuable information such as source and destination IP addresses, protocols, and payload data. It leverages the Scapy library for packet manipulation and analysis and uses the logging module to persist captured data. Running the script with appropriate setup and permissions allows successful packet capture and analysis for educational or debugging purposes.

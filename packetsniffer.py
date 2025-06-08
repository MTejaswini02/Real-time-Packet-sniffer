import argparse
import json
import csv
import threading
import time
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from scapy.all import sniff, IP, TCP, UDP, wrpcap

# Global variables
packet_count = 0
times = []
counts = []
syn_packets = {}
packets_log = []
captured_packets = []
ani = None  # Store animation reference

def packet_callback(packet):
    global packet_count
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        sport, dport, proto = None, None, "OTHER"

        if packet.haslayer(TCP):
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # Correct SYN flag check
            if packet[TCP].flags & 2:  # SYN flag
                syn_packets[ip_src] = syn_packets.get(ip_src, 0) + 1
                if syn_packets[ip_src] > 100:
                    print(f"SYN flood attack detected from {ip_src}")
        
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        # Store packet details
        packet_info = {
            "timestamp": time.time(),
            "protocol": proto,
            "source_ip": ip_src,
            "source_port": sport,
            "destination_ip": ip_dst,
            "destination_port": dport
        }
        packets_log.append(packet_info)
        captured_packets.append(packet)
        print(f"{proto} Packet: {ip_src}:{sport} -> {ip_dst}:{dport}")
        
        packet_count += 1

def update(frame):
    times.append(time.time())
    counts.append(packet_count)
    plt.cla()
    plt.plot(times, counts, label='Packets over time')
    plt.xlabel('Time')
    plt.ylabel('Packet Count')
    plt.legend(loc='upper left')

def save_logs_as_json(filename):
    if not packets_log:
        print("No packets captured, skipping JSON log.")
        return
    with open(filename, 'w') as f:
        json.dump(packets_log, f, indent=4)

def save_logs_as_csv(filename):
    if not packets_log:
        print("No packets captured, skipping CSV log.")
        return
    keys = packets_log[0].keys()
    with open(filename, 'w', newline='') as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(packets_log)

def start_sniffing(duration):
    print("Starting packet sniffing...")
    sniff(prn=packet_callback, filter="tcp or udp", store=0, timeout=duration)
    if captured_packets:
        wrpcap('captured_packets.pcap', captured_packets)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Packet Sniffer")
    parser.add_argument('--duration', type=int, default=60, help='Capture duration in seconds')
    parser.add_argument('--log-format', choices=['json', 'csv'], default='json', help='Format to save the logs')
    args = parser.parse_args()
    
    # Start packet sniffing in a separate thread
    sniffer_thread = threading.Thread(target=start_sniffing, args=(args.duration,), daemon=True)
    sniffer_thread.start()
    
    # Start real-time visualization in main thread
    fig = plt.figure()
    ani = FuncAnimation(fig, update, interval=1000)  # Store animation object
    plt.show()  # Run Matplotlib GUI in the main thread
    
    sniffer_thread.join()
    
    print("Packet capture completed.")
    if args.log_format == 'json':
        save_logs_as_json('packets_log.json')
    elif args.log_format == 'csv':
        save_logs_as_csv('packets_log.csv')
    print(f"Logs saved as {args.log_format}")


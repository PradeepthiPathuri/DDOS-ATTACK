from scapy.all import AsyncSniffer, IP
import csv
import os
from datetime import datetime

LOG_FILE = "data/traffic_log.csv"
sniffer = None

def initialize_csv():
    if not os.path.exists("data"):
        os.makedirs("data")

    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "ttl"])

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        ttl = packet[IP].ttl
        timestamp = datetime.now()

        with open(LOG_FILE, "a", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, src_ip, dst_ip, protocol, ttl])

        print(f"Captured: {src_ip} → {dst_ip} | TTL: {ttl}")

def start_sniffing():
    global sniffer
    if sniffer is None or not sniffer.running:
        initialize_csv()
        sniffer = AsyncSniffer(prn=process_packet, store=False)
        sniffer.start()
        print("Sniffing Started")

def stop_sniffing():
    global sniffer
    if sniffer and sniffer.running:
        sniffer.stop()
        print("Sniffing Stopped")

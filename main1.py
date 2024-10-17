from scapy.all import *
from collections import defaultdict
import time

port_scan_dict = defaultdict(list)
syn_floodcd_dict = defaultdict(int)

def detect_port_scan(packet):
    if TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        if dst_port not in port_scan_dict[src_ip]:
            port_scan_dict[src_ip].append(dst_port)
        
        if len(port_scan_dict[src_ip]) > 10:
            print(f"[ALERT] Port scan detected from {src_ip}")
            with open("alerts.log", "a") as f:
                f.write(f"Port scan detected from {src_ip} on {time.ctime()}\n")
            port_scan_dict[src_ip] = []  

def detect_syn_flood(packet):
    if TCP in packet and packet[TCP].flags == "S":  
        src_ip = packet[IP].src
        syn_flood_dict[src_ip] += 1
        
        if syn_flood_dict[src_ip] > 50:
            print(f"[ALERT] SYN Flood attack detected from {src_ip}")
            with open("alerts.log", "a") as f:
                f.write(f"SYN Flood detected from {src_ip} on {time.ctime()}\n")
            syn_flood_dict[src_ip] = 0  

def analyze_packet(packet):
    if IP in packet:
        detect_port_scan(packet)
        detect_syn_flood(packet)

print("Starting network traffic monitoring...")
sniff(prn=analyze_packet, store=0)

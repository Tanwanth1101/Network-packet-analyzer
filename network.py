#!/usr/bin/env python3

from scapy.all import *

def packet_callback(packet):
    # Ignore ARP and ICMP packets
    if packet.haslayer(ARP) or packet.haslayer(ICMP):
        return

    # Print relevant information
    print("Source IP: {}".format(packet[IP].src))
    print("Destination IP: {}".format(packet[IP].dst))
    print("Protocol: {}".format(packet[IP].proto))

    # Print payload data for TCP packets
    if packet.haslayer(TCP):
        print("Payload: {}".format(packet[TCP].payload))

    print("-------------------------------")

# Start the packet sniffer
sniff(prn=packet_callback, filter="tcp", store=0)
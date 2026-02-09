from scapy.all import *

pkts = rdpcap('sampledata.pcap')

tcp_count = 0
udp_count = 0

for pkt in pkts:
    if pkt.haslayer(TCP):
        tcp_count += 1
    elif pkt.haslayer(UDP):
        udp_count += 1

print("Total number of packets in the pcap file:", len(pkts))
print("Total number of tcp packets:", tcp_count)
print("Total number of udp packets:", udp_count)
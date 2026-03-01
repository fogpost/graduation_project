from scapy.all import rdpcap, PcapReader
from pathlib import Path

base_path = Path(__file__).resolve()
# 构建指向 pcap 文件的路径
pcap_file = base_path.parent.parent / 'data' / 'all-xena-pcap' / 'ARP_Spoofing.pcap'

print(f"目标文件路径: {pcap_file}")
print(f"目标文件是否存在: {pcap_file.exists()}")

if pcap_file.exists():
    with PcapReader(str(pcap_file)) as reader:
        count = 0
        for pkt in reader:
            count+=1
            if count<=5:
                print(f"--- Packet {count} ---")
                pkt.show()
            else:
                print(pkt.summary())

            if count>=100:
                break
else:
    print("文件不存在！")

from scapy.all import rdpcap

packets = []

def load_pcap(file_path):
    global packets

    packets[:] = rdpcap(str(file_path))  # 保证修改原列表对象
    print("加载数据包数量:", len(packets))
    print(packets[0].summary())
    return len(packets)
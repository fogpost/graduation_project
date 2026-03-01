import json
from scapy.all import PcapReader,IP,TCP,UDP,ARP,Ether
from pathlib import Path

# 1. 路径设置
base_path = Path(__file__).resolve()
pcap_file = base_path.parent.parent / 'data' / 'all-xena-pcap' / 'ARP_Spoofing.pcap'

# 存储解析后的字典列表
packet_list = []

print(f"开始解析文件: {pcap_file}")

if pcap_file.exists():
    with PcapReader(str(pcap_file)) as reader:
        count=0
        for pkt in reader:
            count+=1
            #1. 构建基础信息
            pkt_data={
                "id": count,
                "time":float(pkt.time),
                "length":len(pkt),
                "summary":pkt.summary()
            }
            #2. 协议分层解析（Scapy）
            if pkt.haslayer(IP):
                pkt_data["protocol"]="IP"
                pkt_data["src"]=pkt[IP].src
                pkt_data["dst"]=pkt[IP].dst

                #细分传输层
                if pkt.haslayer(TCP):
                    pkt_data["type"]="TCP"
                    pkt_data["sport"]=pkt[TCP].sport
                    pkt_data["dport"]=pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    pkt_data["type"]="UDP"
                    pkt_data["sport"]=pkt[UDP].sport
                    pkt_data["dport"]=pkt[UDP].dport
            elif pkt.haslayer(ARP):
                pkt_data["protocol"]="ARP"
                pkt_data["type"]="ARP"
                pkt_data["src"]=pkt[ARP].psrc
                pkt_data["dst"]=pkt[ARP].pdst
                pkt_data["hwsrc"]=pkt[ARP].hwsrc
                pkt_data["hwdst"]=pkt[ARP].hwdst
                pkt_data["op"]=pkt[ARP].op
            
            else:
                pkt_data["protocol"]="Other"
            
            packet_list.append(pkt_data)
            #演示限制:仅处理前100个
            if count>=100:
                break
            
    # 将列表转换为 JSON 字符串
    output_path = base_path.parent/"scapy_analysis.json"
    with open(output_path, 'w') as f:
        json.dump(packet_list, f, indent=4,ensure_ascii=False)

    print(f"解析完成，结果已保存到: {output_path}")
else:
    print("错误：未找到指定的 PCAP 文件，请检查路径。")
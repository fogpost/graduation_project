'''
python包的说明文档，这个包主要是用于识别已经录取的静态包文件，分析其中的协议类型和数量等信息，提供给后续的分析和处理使用。
'''

import dpkt
from pathlib import Path

# 计数器初始化
counter = 0 
ipcounter = 0
tcpcounter = 0
udpcounter = 0

# 获取脚本所在的绝对路径，确保路径解析的准确性
base_path = Path(__file__).resolve()
# 构建指向 pcap 文件的路径
pcap_file = base_path.parent.parent / 'data' / 'all-xena-pcap' / 'ARP_Spoofing.pcap'

print(f"目标文件路径: {pcap_file}")
print(f"目标文件是否存在: {pcap_file.exists()}")

if pcap_file.exists():
    # 使用 with open 自动管理资源
    with open(pcap_file, 'rb') as f:
        # 将文件句柄传递给 dpkt
        reader = dpkt.pcap.Reader(f)
        
        for ts, pkt in reader:
            counter += 1
            
            # 1. 解析以太网层
            try:
                eth = dpkt.ethernet.Ethernet(pkt)
            except:
                continue # 如果解析失败则跳过
                
            # 2. 过滤非 IP 协议
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            # 3. 解析 IP 层
            ip = eth.data
            ipcounter += 1
            
            # 4. 统计传输层协议
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcpcounter += 1
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udpcounter += 1

    # 打印结果
    print("-" * 30)
    print(f"Total packets: {counter}")
    print(f"IP packets:    {ipcounter}")
    print(f"TCP packets:   {tcpcounter}")
    print(f"UDP packets:   {udpcounter}")
else:
    print("错误：未找到指定的 PCAP 文件，请检查路径。")

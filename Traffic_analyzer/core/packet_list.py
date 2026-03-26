from Traffic_analyzer.core.pcap_loader import packets
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP


def get_packet_list(offset: int = 0, limit: int = 200):
    if offset < 0:
        raise ValueError("offset must be >= 0")
    if limit <= 0:
        raise ValueError("limit must be > 0")

    result = []
    end = min(offset + limit, len(packets))
    for i in range(offset, end):
        p = packets[i]
        protocol = p.lastlayer().name if p.lastlayer() else p.name
        src_ip = ""
        dst_ip = ""
        src_port = None
        dst_port = None

        if p.haslayer(IP):
            src_ip = str(p[IP].src)
            dst_ip = str(p[IP].dst)
        elif p.haslayer(ARP):
            src_ip = str(getattr(p[ARP], "psrc", ""))
            dst_ip = str(getattr(p[ARP], "pdst", ""))

        if p.haslayer(TCP):
            src_port = int(p[TCP].sport)
            dst_port = int(p[TCP].dport)
            protocol = "TCP"
        elif p.haslayer(UDP):
            src_port = int(p[UDP].sport)
            dst_port = int(p[UDP].dport)
            protocol = "UDP"
        elif p.haslayer(ARP):
            protocol = "ARP"
        elif p.haslayer(IP):
            protocol = "IP"

        brief = f"{src_ip or '-'} -> {dst_ip or '-'}"
        info = {
            "id": i,
            "summary": brief,
            "length": len(p),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
        }
        result.append(info)

    return {
        "total": len(packets),
        "offset": offset,
        "limit": limit,
        "items": result,
    }

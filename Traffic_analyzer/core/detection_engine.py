from collections import Counter, defaultdict
from datetime import datetime, timezone

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP

from Traffic_analyzer.core.pcap_loader import packets

RULE_LIBRARY = [
    {
        "id": "ARP_SPOOF_MULTI_MAC",
        "name": "ARP 欺骗可疑",
        "severity": "high",
        "description": "同一 IP 对应多个 ARP 源 MAC。",
    },
    {
        "id": "TCP_SYN_FLOOD",
        "name": "SYN Flood 可疑",
        "severity": "high",
        "description": "单源发送大量 SYN 且无 ACK 对应。",
    },
    {
        "id": "DNS_QUERY_FLOOD",
        "name": "DNS 请求洪泛可疑",
        "severity": "medium",
        "description": "单源在短样本中向 53 端口发送大量 UDP 请求。",
    },
    {
        "id": "ICMP_ECHO_FLOOD",
        "name": "ICMP Flood 可疑",
        "severity": "medium",
        "description": "单源发送大量 ICMP Echo 请求。",
    },
    {
        "id": "TCP_PORT_SCAN",
        "name": "端口扫描可疑",
        "severity": "medium",
        "description": "单源短时间触达大量目的端口。",
    },
]


def _top_items(counter: Counter, limit: int = 10):
    return [{"key": k, "count": v} for k, v in counter.most_common(limit)]


def build_detection_report():
    packet_count = len(packets)
    if packet_count == 0:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "packet_count": 0,
            "feature_stats": {
                "protocol_counts": [],
                "top_src_ips": [],
                "top_dst_ips": [],
                "unique_src_ips": 0,
                "unique_dst_ips": 0,
            },
            "rules": RULE_LIBRARY,
            "alerts": [],
        }

    protocol_counter = Counter()
    src_counter = Counter()
    dst_counter = Counter()

    arp_ip_to_macs = defaultdict(set)
    arp_packet_ids = defaultdict(list)
    syn_counter = Counter()
    syn_packet_ids = defaultdict(list)
    dns_counter = Counter()
    dns_packet_ids = defaultdict(list)
    icmp_counter = Counter()
    icmp_packet_ids = defaultdict(list)
    scan_ports = defaultdict(set)
    scan_packet_ids = defaultdict(list)

    for idx, pkt in enumerate(packets):
        src_ip = None
        dst_ip = None

        if pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip = str(ip.src)
            dst_ip = str(ip.dst)
            protocol_counter["IP"] += 1
        elif pkt.haslayer(ARP):
            arp = pkt[ARP]
            src_ip = str(getattr(arp, "psrc", ""))
            dst_ip = str(getattr(arp, "pdst", ""))
            protocol_counter["ARP"] += 1
        else:
            protocol_counter[pkt.name] += 1

        if src_ip:
            src_counter[src_ip] += 1
        if dst_ip:
            dst_counter[dst_ip] += 1

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            if int(getattr(arp, "op", 0)) in {1, 2}:
                psrc = str(getattr(arp, "psrc", ""))
                hwsrc = str(getattr(arp, "hwsrc", ""))
                if psrc and hwsrc:
                    arp_ip_to_macs[psrc].add(hwsrc)
                    arp_packet_ids[psrc].append(idx)

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)
            if syn and not ack and src_ip:
                syn_counter[src_ip] += 1
                scan_ports[src_ip].add(int(tcp.dport))
                syn_packet_ids[src_ip].append(idx)
                scan_packet_ids[src_ip].append(idx)

        if pkt.haslayer(UDP) and src_ip:
            udp = pkt[UDP]
            if int(udp.dport) == 53:
                dns_counter[src_ip] += 1
                dns_packet_ids[src_ip].append(idx)

        if pkt.haslayer(ICMP) and src_ip:
            icmp = pkt[ICMP]
            if int(getattr(icmp, "type", -1)) == 8:
                icmp_counter[src_ip] += 1
                icmp_packet_ids[src_ip].append(idx)

    alerts = []

    for ip, macs in arp_ip_to_macs.items():
        if len(macs) > 1:
            matched_packets = sorted(set(arp_packet_ids[ip]))
            alerts.append(
                {
                    "rule_id": "ARP_SPOOF_MULTI_MAC",
                    "severity": "high",
                    "title": "同一 IP 出现多个 ARP 源 MAC",
                    "description": "检测到 ARP 应答映射冲突，存在 ARP 欺骗风险。",
                    "alert_ip": ip,
                    "evidence": {
                        "ip": ip,
                        "macs": sorted(macs),
                        "mac_count": len(macs),
                        "packet_ids": matched_packets[:50],
                        "primary_packet_id": matched_packets[0] if matched_packets else None,
                    },
                    "recommendation": "核查网关 ARP 绑定，启用动态 ARP 防护并抓取更长时间样本复核。",
                }
            )

    syn_threshold = max(10, int(packet_count * 0.1))
    for src, count in syn_counter.items():
        if count >= syn_threshold:
            matched_packets = sorted(set(syn_packet_ids[src]))
            alerts.append(
                {
                    "rule_id": "TCP_SYN_FLOOD",
                    "severity": "high",
                    "title": "疑似 SYN Flood",
                    "description": "单源 SYN 请求量异常偏高。",
                    "alert_ip": src,
                    "evidence": {
                        "src_ip": src,
                        "syn_count": count,
                        "threshold": syn_threshold,
                        "packet_ids": matched_packets[:50],
                        "primary_packet_id": matched_packets[0] if matched_packets else None,
                    },
                    "recommendation": "检查边界防火墙/IPS 的 SYN 限速策略并联动黑名单。",
                }
            )

    dns_threshold = max(10, int(packet_count * 0.1))
    for src, count in dns_counter.items():
        if count >= dns_threshold:
            matched_packets = sorted(set(dns_packet_ids[src]))
            alerts.append(
                {
                    "rule_id": "DNS_QUERY_FLOOD",
                    "severity": "medium",
                    "title": "疑似 DNS 请求洪泛",
                    "description": "单源对 DNS 端口的 UDP 请求量异常偏高。",
                    "alert_ip": src,
                    "evidence": {
                        "src_ip": src,
                        "dns_request_count": count,
                        "threshold": dns_threshold,
                        "packet_ids": matched_packets[:50],
                        "primary_packet_id": matched_packets[0] if matched_packets else None,
                    },
                    "recommendation": "核查该主机业务角色，必要时对 DNS 请求做速率限制。",
                }
            )

    icmp_threshold = max(10, int(packet_count * 0.1))
    for src, count in icmp_counter.items():
        if count >= icmp_threshold:
            matched_packets = sorted(set(icmp_packet_ids[src]))
            alerts.append(
                {
                    "rule_id": "ICMP_ECHO_FLOOD",
                    "severity": "medium",
                    "title": "疑似 ICMP Flood",
                    "description": "单源 ICMP Echo 请求数量异常偏高。",
                    "alert_ip": src,
                    "evidence": {
                        "src_ip": src,
                        "icmp_echo_count": count,
                        "threshold": icmp_threshold,
                        "packet_ids": matched_packets[:50],
                        "primary_packet_id": matched_packets[0] if matched_packets else None,
                    },
                    "recommendation": "建议在边界设备启用 ICMP 限速并定位来源主机。",
                }
            )

    scan_threshold = 20
    for src, ports in scan_ports.items():
        if len(ports) >= scan_threshold:
            matched_packets = sorted(set(scan_packet_ids[src]))
            alerts.append(
                {
                    "rule_id": "TCP_PORT_SCAN",
                    "severity": "medium",
                    "title": "疑似端口扫描",
                    "description": "单源访问目的端口数量异常偏高。",
                    "alert_ip": src,
                    "evidence": {
                        "src_ip": src,
                        "unique_dst_ports": len(ports),
                        "threshold": scan_threshold,
                        "packet_ids": matched_packets[:50],
                        "primary_packet_id": matched_packets[0] if matched_packets else None,
                    },
                    "recommendation": "关注该主机连接行为，结合防火墙日志确认扫描意图。",
                }
            )

    for idx, alert in enumerate(alerts, start=1):
        alert["alert_id"] = f"ALERT-{idx:04d}"

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "packet_count": packet_count,
        "feature_stats": {
            "protocol_counts": _top_items(protocol_counter),
            "top_src_ips": _top_items(src_counter),
            "top_dst_ips": _top_items(dst_counter),
            "unique_src_ips": len(src_counter),
            "unique_dst_ips": len(dst_counter),
        },
        "rules": RULE_LIBRARY,
        "alerts": alerts,
    }

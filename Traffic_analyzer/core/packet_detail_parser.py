from Traffic_analyzer.core.pcap_loader import packets

LAYER_LABELS = {
    "Ethernet": "以太网帧",
    "Dot1Q": "VLAN 标签",
    "IP": "IPv4 报文头",
    "IPv6": "IPv6 报文头",
    "TCP": "TCP 传输层",
    "UDP": "UDP 传输层",
    "ICMP": "ICMP 控制报文",
    "ARP": "ARP 地址解析",
    "DNS": "DNS 域名系统",
    "Raw": "应用负载",
}

FIELD_LABELS = {
    "src": "源地址",
    "dst": "目的地址",
    "sport": "源端口",
    "dport": "目的端口",
    "ttl": "生存时间 TTL",
    "len": "总长度",
    "ihl": "首部长度",
    "version": "IP 版本",
    "flags": "标志位",
    "chksum": "校验和",
    "seq": "序列号",
    "ack": "确认号",
    "window": "窗口大小",
    "urgptr": "紧急指针",
    "proto": "上层协议",
    "op": "ARP 操作",
    "hwsrc": "源 MAC",
    "hwdst": "目的 MAC",
    "psrc": "源 IP",
    "pdst": "目的 IP",
    "type": "ICMP 类型",
    "code": "ICMP 代码",
}

PORT_HINTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
}

IP_PROTO_HINTS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}

ARP_OP_HINTS = {
    1: "ARP Request",
    2: "ARP Reply",
}

ICMP_TYPE_HINTS = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
}


def _safe_int(value):
    try:
        return int(value)
    except Exception:
        return None


def _decode_tcp_flags(value: int) -> str:
    bit_names = [
        (0x100, "NS"),
        (0x080, "CWR"),
        (0x040, "ECE"),
        (0x020, "URG"),
        (0x010, "ACK"),
        (0x008, "PSH"),
        (0x004, "RST"),
        (0x002, "SYN"),
        (0x001, "FIN"),
    ]
    names = [name for bit, name in bit_names if value & bit]
    return "|".join(names) if names else "NONE"


def _field_label(field_name: str) -> str:
    return FIELD_LABELS.get(field_name, field_name)


def _layer_label(layer_name: str) -> str:
    return LAYER_LABELS.get(layer_name, layer_name)


def _friendly_value(layer_name: str, field_name: str, value) -> str:
    ivalue = _safe_int(value)

    if field_name in {"sport", "dport"} and ivalue is not None:
        service = PORT_HINTS.get(ivalue)
        return f"{ivalue} ({service})" if service else str(ivalue)

    if field_name == "proto" and ivalue is not None:
        proto = IP_PROTO_HINTS.get(ivalue)
        return f"{ivalue} ({proto})" if proto else str(ivalue)

    if field_name == "op" and ivalue is not None:
        op = ARP_OP_HINTS.get(ivalue)
        return f"{ivalue} ({op})" if op else str(ivalue)

    if layer_name == "TCP" and field_name == "flags" and ivalue is not None:
        return f"0x{ivalue:03x} ({_decode_tcp_flags(ivalue)})"

    if layer_name in {"ICMP", "ICMPv6"} and field_name == "type" and ivalue is not None:
        hint = ICMP_TYPE_HINTS.get(ivalue)
        return f"{ivalue} ({hint})" if hint else str(ivalue)

    if field_name == "ttl" and ivalue is not None:
        return f"{ivalue} hops"

    if field_name in {"len", "window", "ihl"} and ivalue is not None:
        return f"{ivalue} bytes"

    return str(value)


def _safe_field_len(field, layer, value) -> int:
    try:
        encoded = field.i2m(layer, value)
        if isinstance(encoded, bytes):
            return len(encoded)
    except Exception:
        pass

    size = getattr(field, "sz", None)
    if isinstance(size, int) and size > 0:
        return size

    return 1


def _safe_field_repr(field, layer, value) -> str:
    try:
        return str(field.i2repr(layer, value))
    except Exception:
        return str(value)


def parse_packet_detail(packet_id: int):
    if packet_id < 0 or packet_id >= len(packets):
        raise IndexError(f"packet_id out of range: {packet_id}")

    pkt = packets[packet_id]
    raw_bytes = bytes(pkt)

    result = {
        "id": packet_id,
        "summary": pkt.summary(),
        "length": len(pkt),
        "raw_hex": raw_bytes.hex(),
        "layers": [],
    }

    current = pkt
    current_offset = 0

    while current:
        if current.name == "Padding":
            current = current.payload
            continue

        payload_len = len(current.payload) if hasattr(current, "payload") else 0
        header_len = max(len(current) - payload_len, 0)

        layer_info = {
            "layer_name": current.name,
            "layer_label": _layer_label(current.name),
            "start": current_offset,
            "end": current_offset + header_len,
            "fields": [],
        }

        field_cursor = current_offset
        layer_end = current_offset + header_len

        for field in getattr(current, "fields_desc", []):
            field_name = field.name
            if field_name not in current.fields:
                continue

            value = current.getfieldval(field_name)
            raw_repr = _safe_field_repr(field, current, value)
            field_len = _safe_field_len(field, current, value)
            remaining = max(layer_end - field_cursor, 0)
            if remaining == 0:
                field_len = 0
            else:
                field_len = min(field_len, remaining)

            layer_info["fields"].append(
                {
                    "name": field_name,
                    "label": _field_label(field_name),
                    "value": raw_repr,
                    "readable_value": _friendly_value(current.name, field_name, value),
                    "offset": field_cursor,
                    "length": field_len,
                }
            )
            field_cursor += field_len

        result["layers"].append(layer_info)
        current_offset += header_len
        current = current.payload

        if not current or isinstance(current, (bytes, str)):
            break

    return result

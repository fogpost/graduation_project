import json
from pathlib import Path
from scapy.all import PcapReader
from scapy.packet import Raw, Padding


# =============================
# 获取层字段信息 + offset
# =============================
def parse_layer(layer, start_offset):
    layer_len = len(layer) - len(layer.payload)

    layer_info = {
        "layer": layer.name,
        "start": start_offset,
        "end": start_offset + layer_len,
        "length": layer_len,
        "fields": {}
    }

    field_offset = start_offset

    for field in layer.fields_desc:

        field_name = field.name

        if field_name not in layer.fields:
            continue

        value = layer.getfieldval(field_name)

        try:
            raw_bytes = field.i2m(layer, value)
            flen = len(raw_bytes)
        except Exception:
            flen = getattr(field, "sz", 0)

        layer_info["fields"][field_name] = {
            "value": str(field.i2repr(layer, value)),
            "offset": field_offset,
            "length": flen
        }

        field_offset += flen

    return layer_info, layer_len


# =============================
# 解析整个数据包
# =============================
def parse_packet(pkt):

    layers = []

    current_offset = 0
    layer = pkt

    while layer:

        if isinstance(layer, (Raw, Padding)):
            raw_bytes = bytes(layer)

            layers.append({
                "layer": layer.name,
                "start": current_offset,
                "end": current_offset + len(raw_bytes),
                "length": len(raw_bytes),
                "fields": {
                    "load": {
                        "value": repr(raw_bytes),
                        "offset": current_offset,
                        "length": len(raw_bytes)
                    }
                }
            })

            break

        layer_info, layer_len = parse_layer(layer, current_offset)

        layers.append(layer_info)

        current_offset += layer_len
        layer = layer.payload

        if not layer:
            break

    return layers


# =============================
# 主函数
# =============================
def pcap_to_json(pcap_path, output_path, limit=100):

    packets = []

    with PcapReader(str(pcap_path)) as reader:

        for i, pkt in enumerate(reader, start=1):

            raw_bytes = bytes(pkt)

            pkt_info = {
                "id": i,
                "time": float(pkt.time),
                "length": len(raw_bytes),
                "raw_hex": raw_bytes.hex(),
                "structure": parse_packet(pkt)
            }

            packets.append(pkt_info)

            if i >= limit:
                break

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(packets, f, indent=4, ensure_ascii=False)

    print("解析完成:", output_path)


# =============================
# 程序入口
# =============================
if __name__ == "__main__":

    base = Path(__file__).resolve().parent

    pcap_file = base.parent / "data" / "all-xena-pcap" /"ARP_Spoofing.pcap"

    output_dir = base / "output"
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / f"{pcap_file.stem}.json"

    pcap_to_json(pcap_file, output_file, limit=50)

# =============================
# 函数调用入口
# =============================

def parse_pcap_file(pcap_path,limit=50):
    """
    解析指定 pcap 文件，生成 JSON 输出到根目录 output
    返回 JSON 文件路径
    """
    base = Path(__file__).resolve().parent.parent  # 根目录
    pcap_path = Path(pcap_path)

    output_dir = base / "output"
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / f"{pcap_path.stem}.json"

    pcap_to_json(pcap_path, output_file, limit=limit)

    return output_file
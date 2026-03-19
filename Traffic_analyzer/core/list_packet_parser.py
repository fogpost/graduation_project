from Traffic_analyzer.core.pcap_loader import packets


def parse_packet(packet_id: int):
    if packet_id < 0 or packet_id >= len(packets):
        raise IndexError(f"packet_id out of range: {packet_id}")

    p = packets[packet_id]
    result = {"layers": []}
    current = p

    while current:
        if current.name != "Padding":
            layer = {
                "layer_name": current.name,
                "fields": {k: str(v) for k, v in current.fields.items()},
            }
            result["layers"].append(layer)
        current = current.payload

    return result

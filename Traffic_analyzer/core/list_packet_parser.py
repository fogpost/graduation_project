from core.pcap_loader import packets

def parse_packet(packet_id):
    p = packets[packet_id]
    result = {
        "layers": []
    }
    current = p

    while current:
        if current.name != "Padding":
            layer = {
                "layer_name": current.name,
                "fields": {k: str(v) for k, v in current.fields.items()}
            }
            result["layers"].append(layer)
        current = current.payload

    return result
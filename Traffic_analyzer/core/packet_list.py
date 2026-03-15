from core.pcap_loader import packets

def get_packet_list():
    result = []

    for i, p in enumerate(packets):

        info = {
            "id": i,
            "summary": p.summary(),
            "length": len(p)
        }

        result.append(info)

    return result
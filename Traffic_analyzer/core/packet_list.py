from Traffic_analyzer.core.pcap_loader import packets


def get_packet_list(offset: int = 0, limit: int = 200):
    if offset < 0:
        raise ValueError("offset must be >= 0")
    if limit <= 0:
        raise ValueError("limit must be > 0")

    result = []
    end = min(offset + limit, len(packets))
    for i in range(offset, end):
        p = packets[i]
        info = {
            "id": i,
            "summary": p.summary(),
            "length": len(p),
        }
        result.append(info)

    return {
        "total": len(packets),
        "offset": offset,
        "limit": limit,
        "items": result,
    }

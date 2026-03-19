from pathlib import Path
from typing import List

from scapy.all import Packet, rdpcap

packets: List[Packet] = []


def load_pcap(file_path: str | Path) -> int:
    pcap_path = Path(file_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    if pcap_path.is_dir():
        raise IsADirectoryError(f"Expected a file path, got directory: {pcap_path}")

    loaded_packets = rdpcap(str(pcap_path))
    packets[:] = loaded_packets
    return len(packets)

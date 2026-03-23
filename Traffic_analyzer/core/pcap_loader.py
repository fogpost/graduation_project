from pathlib import Path
from typing import List

from scapy.all import Packet, rdpcap
from scapy.error import Scapy_Exception

packets: List[Packet] = []
loaded_pcap_path: Path | None = None


def load_pcap(file_path: str | Path) -> int:
    global loaded_pcap_path

    pcap_path = Path(file_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    if pcap_path.is_dir():
        raise IsADirectoryError(f"Expected a file path, got directory: {pcap_path}")
    if pcap_path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise ValueError(f"Unsupported pcap file type: {pcap_path.suffix}")

    try:
        loaded_packets = rdpcap(str(pcap_path))
    except Scapy_Exception as exc:
        raise ValueError(f"Invalid or unsupported pcap content: {pcap_path.name}") from exc

    packets[:] = loaded_packets
    loaded_pcap_path = pcap_path.resolve()
    return len(packets)

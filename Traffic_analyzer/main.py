from fastapi import FastAPI

from core.pcap_loader import load_pcap
from core.packet_list import get_packet_list
from core.list_packet_parser import parse_packet

app = FastAPI()

# 启动时加载PCAP
load_pcap("data/test/all-xena-pcap/ARP_Spoofing.pcap")

@app.get("/load")
def load():
    count = load_pcap("data/test/all-xena-pcap/ARP_Spoofing.pcap")
    return {"packet_count": count}

@app.get("/packets")
def packets():
    return get_packet_list()


@app.get("/packet/{packet_id}")
def packet(packet_id: int):
    return parse_packet(packet_id)
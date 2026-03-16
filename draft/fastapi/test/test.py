from fastapi import FastAPI
from parse_pcap import parse_pcap

app = FastAPI()

@app.get("/pcap")
def pcap():
    data = parse_pcap("test.pcap")
    return data
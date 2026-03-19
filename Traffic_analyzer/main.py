from contextlib import asynccontextmanager
from pathlib import Path
import os

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from Traffic_analyzer.core.list_packet_parser import parse_packet
from Traffic_analyzer.core.packet_list import get_packet_list
from Traffic_analyzer.core.pcap_loader import load_pcap

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_PCAP = BASE_DIR / "data" / "test" / "all-xena-pcap" / "ARP_Spoofing.pcap"
PCAP_ON_STARTUP = Path(os.getenv("PCAP_ON_STARTUP", str(DEFAULT_PCAP)))


@asynccontextmanager
async def lifespan(_: FastAPI):
    if PCAP_ON_STARTUP.exists():
        load_pcap(PCAP_ON_STARTUP)
    yield


app = FastAPI(title="Traffic Analyzer API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/load")
@app.get("/load")
def load(file_path: str | None = Query(default=None, description="PCAP file path")):
    target = Path(file_path) if file_path else PCAP_ON_STARTUP
    try:
        count = load_pcap(target)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except IsADirectoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"Failed to load pcap: {exc}") from exc

    return {
        "packet_count": count,
        "file": str(target),
    }


@app.get("/packets")
def packets(
    offset: int = Query(default=0, ge=0, description="Start index"),
    limit: int = Query(default=200, ge=1, le=2000, description="Page size"),
):
    try:
        return get_packet_list(offset=offset, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/packet/{packet_id}")
def packet(packet_id: int):
    try:
        return parse_packet(packet_id)
    except IndexError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

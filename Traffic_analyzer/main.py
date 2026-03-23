from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
import os
import shutil

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from Traffic_analyzer.core.pcap_catalog import (
    DATA_ROOT,
    get_next_data_file,
    list_data_pcap_files,
    resolve_data_relative_path,
    set_sequence_cursor_from_path,
)
from Traffic_analyzer.core.packet_detail_parser import parse_packet_detail
from Traffic_analyzer.core.list_packet_parser import parse_packet
from Traffic_analyzer.core.packet_list import get_packet_list
from Traffic_analyzer.core.detection_engine import RULE_LIBRARY, build_detection_report
from Traffic_analyzer.core import pcap_loader

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_PCAP = DATA_ROOT / "test" / "all-xena-pcap" / "ARP_Spoofing.pcap"
PCAP_ON_STARTUP = Path(os.getenv("PCAP_ON_STARTUP", str(DEFAULT_PCAP)))
UPLOAD_DIR = DATA_ROOT / "imported"
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")
ORIGINS = ["*"] if ALLOWED_ORIGINS.strip() == "*" else [x.strip() for x in ALLOWED_ORIGINS.split(",") if x.strip()]


@asynccontextmanager
async def lifespan(_: FastAPI):
    if PCAP_ON_STARTUP.exists():
        pcap_loader.load_pcap(PCAP_ON_STARTUP)
        set_sequence_cursor_from_path(PCAP_ON_STARTUP)
    yield


app = FastAPI(title="Traffic Analyzer API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGINS,
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
        count = pcap_loader.load_pcap(target)
        set_sequence_cursor_from_path(target)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except IsADirectoryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"Failed to load pcap: {exc}") from exc

    return {
        "packet_count": count,
        "file": str(target),
    }


@app.get("/pcap-files")
def pcap_files():
    items = list_data_pcap_files()
    current_file = str(pcap_loader.loaded_pcap_path) if pcap_loader.loaded_pcap_path else None
    return {
        "root": str(DATA_ROOT.resolve()),
        "count": len(items),
        "current_file": current_file,
        "items": items,
    }


@app.post("/load-data-file")
def load_data_file(
    relative_path: str = Query(..., description="Path relative to Traffic_analyzer/data"),
):
    try:
        target = resolve_data_relative_path(relative_path)
        count = pcap_loader.load_pcap(target)
        set_sequence_cursor_from_path(target)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"Failed to load pcap: {exc}") from exc

    return {
        "packet_count": count,
        "file": str(target),
    }


@app.post("/load-next-data-file")
def load_next_data_file():
    item = get_next_data_file()
    if item is None:
        raise HTTPException(status_code=404, detail="No pcap files found under data directory")

    target = Path(item["absolute_path"])
    try:
        count = pcap_loader.load_pcap(target)
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"Failed to load pcap: {exc}") from exc

    return {
        "packet_count": count,
        "file": str(target),
        "relative_path": item["relative_path"],
        "index": item["index"],
    }


@app.post("/upload-pcap")
def upload_pcap(file: UploadFile = File(...)):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {suffix or 'unknown'}")

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_name = Path(file.filename).name.replace(" ", "_")
    target = UPLOAD_DIR / f"{timestamp}_{safe_name}"

    try:
        with target.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        count = pcap_loader.load_pcap(target)
        set_sequence_cursor_from_path(target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"Failed to upload and load pcap: {exc}") from exc
    finally:
        file.file.close()

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


@app.get("/packet/{packet_id}/detail")
def packet_detail(packet_id: int):
    try:
        return parse_packet_detail(packet_id)
    except IndexError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/analysis/rules")
def analysis_rules():
    return {"count": len(RULE_LIBRARY), "items": RULE_LIBRARY}


@app.get("/analysis/report")
def analysis_report():
    return build_detection_report()

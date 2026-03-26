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
PCAP_ON_STARTUP_ENV = os.getenv("PCAP_ON_STARTUP", "").strip()
PCAP_ON_STARTUP = Path(PCAP_ON_STARTUP_ENV) if PCAP_ON_STARTUP_ENV else None
UPLOAD_DIR = DATA_ROOT / "imported"
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")
ORIGINS = ["*"] if ALLOWED_ORIGINS.strip() == "*" else [x.strip() for x in ALLOWED_ORIGINS.split(",") if x.strip()]


@asynccontextmanager
async def lifespan(_: FastAPI):
    if PCAP_ON_STARTUP and PCAP_ON_STARTUP.exists():
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
    if file_path:
        target = Path(file_path)
    elif PCAP_ON_STARTUP:
        target = PCAP_ON_STARTUP
    else:
        raise HTTPException(status_code=400, detail="No startup pcap configured, please provide file_path")
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


@app.delete("/data-file")
def delete_data_file(
    relative_path: str = Query(..., description="Path relative to Traffic_analyzer/data"),
):
    try:
        target = resolve_data_relative_path(relative_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail=f"File not found: {relative_path}")

    loaded = pcap_loader.loaded_pcap_path
    is_loaded_file = loaded is not None and loaded.resolve() == target.resolve()

    try:
        target.unlink()
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"Failed to delete file: {exc}") from exc

    if is_loaded_file:
        pcap_loader.packets.clear()
        pcap_loader.loaded_pcap_path = None

    return {
        "deleted": True,
        "relative_path": relative_path,
        "was_loaded_file": is_loaded_file,
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


@app.delete("/packet/{packet_id}")
def delete_packet(packet_id: int):
    if packet_id < 0 or packet_id >= len(pcap_loader.packets):
        raise HTTPException(status_code=404, detail=f"packet_id out of range: {packet_id}")

    del pcap_loader.packets[packet_id]
    return {
        "deleted": True,
        "packet_id": packet_id,
        "remaining": len(pcap_loader.packets),
    }


@app.get("/analysis/rules")
def analysis_rules():
    return {"count": len(RULE_LIBRARY), "items": RULE_LIBRARY}


@app.get("/analysis/report")
def analysis_report():
    return build_detection_report()

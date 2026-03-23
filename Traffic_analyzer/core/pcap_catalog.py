from pathlib import Path
from typing import Dict, List, Optional
import os

DEFAULT_DATA_ROOT = Path(__file__).resolve().parent.parent / "data"
DATA_ROOT = Path(os.getenv("TRAFFIC_ANALYZER_DATA_DIR", str(DEFAULT_DATA_ROOT))).resolve()
SUPPORTED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

_sequence_cursor = 0


def _as_posix(path: Path) -> str:
    return str(path).replace("\\", "/")


def list_data_pcap_files() -> List[Dict[str, str]]:
    if not DATA_ROOT.exists():
        return []

    files = [
        path
        for path in DATA_ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS
    ]
    files.sort(key=lambda p: _as_posix(p.relative_to(DATA_ROOT)).lower())

    items: List[Dict[str, str]] = []
    for index, file_path in enumerate(files):
        relative = file_path.relative_to(DATA_ROOT)
        items.append(
            {
                "index": index,
                "name": file_path.name,
                "relative_path": _as_posix(relative),
                "absolute_path": str(file_path.resolve()),
                "size": file_path.stat().st_size,
                "modified_at": file_path.stat().st_mtime,
            }
        )

    return items


def resolve_data_relative_path(relative_path: str) -> Path:
    if not relative_path.strip():
        raise ValueError("relative_path cannot be empty")

    candidate = (DATA_ROOT / relative_path).resolve()
    try:
        candidate.relative_to(DATA_ROOT.resolve())
    except ValueError as exc:
        raise ValueError("Path must be inside data directory") from exc

    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(f"PCAP file not found in data directory: {relative_path}")
    if candidate.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {candidate.suffix}")

    return candidate


def set_sequence_cursor_from_path(path: Path) -> None:
    global _sequence_cursor
    files = list_data_pcap_files()
    resolved = path.resolve()

    for item in files:
        if Path(item["absolute_path"]).resolve() == resolved:
            _sequence_cursor = item["index"] + 1
            return


def get_next_data_file() -> Optional[Dict[str, str]]:
    global _sequence_cursor
    files = list_data_pcap_files()
    if not files:
        return None

    if _sequence_cursor >= len(files):
        _sequence_cursor = 0

    item = files[_sequence_cursor]
    _sequence_cursor += 1
    return item


import hashlib
import json
from pathlib import Path

from evtx_parser import parse_evtx

CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(exist_ok=True)

CACHE_VERSION = 1


def load_events(file_path):
    path = Path(file_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")

    stat = path.stat()

    # Unique cache filename for each source path.
    cache_key = hashlib.sha256(
        str(path).encode("utf-8")
    ).hexdigest()

    cache_file = CACHE_DIR / f"{cache_key}.json"

    # Check whether the source file has changed.
    if cache_file.exists():
        try:
            with cache_file.open("r", encoding="utf-8") as file:
                cached = json.load(file)

            if (
                cached.get("version") == CACHE_VERSION
                and cached.get("file_size") == stat.st_size
                and cached.get("modified_ns") == stat.st_mtime_ns
            ):
                print("Loading cached events...")
                return cached["events"]

        except (OSError, ValueError, KeyError, TypeError):
            print("Cache invalid. Rebuilding...")

    print("Parsing EVTX file...")
    events = parse_evtx(str(path))

    cache_data = {
        "version": CACHE_VERSION,
        "file_size": stat.st_size,
        "modified_ns": stat.st_mtime_ns,
        "events": events
    }

    # Write to a temporary file first to avoid partial caches.
    temp_file = cache_file.with_suffix(".tmp")

    with temp_file.open("w", encoding="utf-8") as file:
        json.dump(cache_data, file)

    temp_file.replace(cache_file)

    print("Cache saved successfully.")
    return events

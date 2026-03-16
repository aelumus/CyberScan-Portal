"""
CyberScan Portal — background scan worker.

Polls the SQLite database for pending scans, processes them through the ML
pipeline, and writes results back.  Designed to run as a separate Docker
container sharing the same data volume as the API.
"""

import json
import sqlite3
import time
from pathlib import Path

from settings import settings
from scan_engine import process_scan

DB_PATH = str(settings.db_path)
UPLOAD_DIR = settings.upload_dir
POLL_INTERVAL = 2  # seconds between DB polls


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _claim_next() -> tuple[str, dict] | None:
    """Atomically claim the oldest pending scan (SELECT + UPDATE)."""
    with _db() as conn:
        row = conn.execute(
            "SELECT id, data FROM scans WHERE status = 'pending' ORDER BY created_at LIMIT 1"
        ).fetchone()
        if not row:
            return None
        scan_id, data_json = row
        record = json.loads(data_json)
        record["status"] = "processing"
        record["progress_step"] = "starting"
        conn.execute(
            "UPDATE scans SET status = 'processing', data = ? WHERE id = ? AND status = 'pending'",
            (json.dumps(record), scan_id),
        )
        conn.commit()
    return scan_id, record


def _update(scan_id: str, record: dict, status: str | None = None):
    if status:
        record["status"] = status
    with _db() as conn:
        conn.execute(
            "UPDATE scans SET data = ?, status = ? WHERE id = ?",
            (json.dumps(record), record["status"], scan_id),
        )
        conn.commit()


def _find_file(scan_id: str, filename: str) -> Path:
    path = UPLOAD_DIR / f"{scan_id}_{filename}"
    if path.exists():
        return path
    matches = list(UPLOAD_DIR.glob(f"{scan_id}_*"))
    if matches:
        return matches[0]
    raise FileNotFoundError(f"Upload not found for scan {scan_id}")


def _process(scan_id: str, record: dict):
    filename = record["filename"]
    file_path = _find_file(scan_id, filename)

    def on_step(step_name: str):
        record["progress_step"] = step_name
        _update(scan_id, record, status="processing")

    result = process_scan(
        file_path=str(file_path),
        threshold=record.get("threshold", 0.4),
        mode=record.get("mode", "balanced"),
        use_vt=record.get("use_vt", False),
        sha256=record.get("sha256", ""),
        on_step=on_step,
    )

    record.update(result)
    record["status"] = "completed"
    record["progress_step"] = "done"
    _update(scan_id, record, status="completed")


def main():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[worker] Started — polling {DB_PATH} every {POLL_INTERVAL}s")
    print(f"[worker] Upload dir: {UPLOAD_DIR}")

    while True:
        claimed = _claim_next()
        if claimed is None:
            time.sleep(POLL_INTERVAL)
            continue

        scan_id, record = claimed
        print(f"[worker] Processing scan {scan_id} ({record.get('filename', '?')})")

        try:
            _process(scan_id, record)
            print(f"[worker] Scan {scan_id} completed")
        except Exception as exc:
            print(f"[worker] Scan {scan_id} FAILED: {exc}")
            record["status"] = "failed"
            record["progress_step"] = "error"
            record["error"] = str(exc)
            _update(scan_id, record, status="failed")


if __name__ == "__main__":
    main()

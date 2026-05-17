import json
import sqlite3
import time
from pathlib import Path

from scan_engine import process_scan
from settings import settings

DB_PATH = str(settings.db_path)
UPLOAD_DIR = settings.upload_dir
POLL_INTERVAL = 2


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _claim_next() -> tuple[str, dict] | None:
    with _db() as conn:
        row = conn.execute(
            "SELECT id, data FROM scans WHERE status = 'pending' ORDER BY created_at LIMIT 1"
        ).fetchone()
        if not row:
            return None
        scan_id, data_json = row
        scan_entry = json.loads(data_json)
        scan_entry["status"] = "processing"
        scan_entry["progress_step"] = "starting"
        conn.execute(
            "UPDATE scans SET status = 'processing', data = ? WHERE id = ? AND status = 'pending'",
            (json.dumps(scan_entry), scan_id),
        )
        conn.commit()
    return scan_id, scan_entry


def _update_scan(scan_id: str, scan_entry: dict, status: str | None = None):
    if status:
        scan_entry["status"] = status
    with _db() as conn:
        conn.execute(
            "UPDATE scans SET data = ?, status = ? WHERE id = ?",
            (json.dumps(scan_entry), scan_entry["status"], scan_id),
        )
        conn.commit()


def _locate_upload(scan_id: str, filename: str) -> Path:
    candidate = UPLOAD_DIR / f"{scan_id}_{filename}"
    if candidate.exists():
        return candidate
    matches = list(UPLOAD_DIR.glob(f"{scan_id}_*"))
    if matches:
        return matches[0]
    raise FileNotFoundError(f"Upload not found for scan {scan_id}")


def _run_analysis(scan_id: str, scan_entry: dict):
    uploaded_file = _locate_upload(scan_id, scan_entry["filename"])

    def on_step(step_name: str):
        scan_entry["progress_step"] = step_name
        _update_scan(scan_id, scan_entry, status="processing")

    scan_result = process_scan(
        file_path=str(uploaded_file),
        threshold=scan_entry.get("threshold", 0.4),
        mode=scan_entry.get("mode", "balanced"),
        use_vt=scan_entry.get("use_vt", False),
        sha256=scan_entry.get("sha256", ""),
        on_step=on_step,
    )
    scan_entry.update(scan_result)
    scan_entry["status"] = "completed"
    scan_entry["progress_step"] = "done"
    _update_scan(scan_id, scan_entry, status="completed")


def main():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[worker] Started — polling {DB_PATH} every {POLL_INTERVAL}s")
    print(f"[worker] Upload dir: {UPLOAD_DIR}")

    while True:
        claimed = _claim_next()
        if claimed is None:
            time.sleep(POLL_INTERVAL)
            continue

        scan_id, scan_entry = claimed
        print(f"[worker] Processing scan {scan_id} ({scan_entry.get('filename', '?')})")

        try:
            _run_analysis(scan_id, scan_entry)
            print(f"[worker] Scan {scan_id} completed")
        except Exception as exc:
            print(f"[worker] Scan {scan_id} FAILED: {exc}")
            scan_entry["status"] = "failed"
            scan_entry["progress_step"] = "error"
            scan_entry["error"] = str(exc)
            _update_scan(scan_id, scan_entry, status="failed")


if __name__ == "__main__":
    main()

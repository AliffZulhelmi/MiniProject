"""Simple SQLite repository for storing alerts and querying them.

This provides minimal persistence for demo and export scenarios.
"""

from pathlib import Path
import sqlite3
import json
from typing import Iterable, Dict, Any, List
import time


DB_PATH = Path("data/alerts.db")


def _ensure_db(path: Path = DB_PATH):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            detector TEXT NOT NULL,
            payload TEXT NOT NULL,
            ts REAL NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def save_alerts(alerts: Iterable[Dict[str, Any]], path: Path | None = None) -> None:
    """Save alerts produced by detectors. Each alert dict should include a `detector` key."""
    path = Path(path or DB_PATH)
    _ensure_db(path)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    ts = time.time()
    for alert in alerts:
        detector = alert.get("detector", "unknown")
        payload = json.dumps(alert)
        cur.execute("INSERT INTO alerts (detector, payload, ts) VALUES (?,?,?)", (detector, payload, ts))
    conn.commit()
    conn.close()


def list_alerts(path: Path | None = None) -> List[Dict[str, Any]]:
    path = Path(path or DB_PATH)
    if not path.exists():
        return []
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT id, detector, payload, ts FROM alerts ORDER BY ts DESC")
    rows = cur.fetchall()
    conn.close()
    results = []
    for r in rows:
        try:
            payload = json.loads(r[2])
        except Exception:
            payload = {"raw": r[2]}
        results.append({"id": r[0], "detector": r[1], "payload": payload, "ts": r[3]})
    return results


__all__ = ["save_alerts", "list_alerts"]
"""SQLite alert repository entry point."""

"""Very small report builder that exports alerts to CSV.

This is intentionally minimal: read alerts from the repository and write a
CSV export so presenters can attach it to evidence.
"""

import csv
from pathlib import Path
from typing import List, Dict, Any
from mini_wids.storage.repository import list_alerts


def export_alerts_csv(dest: str) -> Path:
    destp = Path(dest)
    destp.parent.mkdir(parents=True, exist_ok=True)
    rows = list_alerts()
    if not rows:
        # write header only
        with open(destp, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["id", "detector", "ts", "payload"])
        return destp

    with open(destp, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["id", "detector", "ts", "payload"])
        for r in rows:
            writer.writerow([r["id"], r["detector"], r["ts"], str(r["payload"])])

    return destp


__all__ = ["export_alerts_csv"]
"""Evidence report builder entry point."""

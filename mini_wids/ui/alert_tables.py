"""Helpers for displaying detector alerts in Streamlit tables."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

import pandas as pd

ALL_DETECTORS = "All Detectors"

DETECTOR_LABELS = {
    "deauth": "Deauth",
    "rogue_ap": "Rogue AP",
    "unknown_device": "Unknown Device",
    "weak_encryption": "Weak Encryption",
}

DETECTOR_ORDER = {
    "Deauth": 0,
    "Rogue AP": 1,
    "Unknown Device": 2,
    "Weak Encryption": 3,
}


def detector_label(detector_id: str) -> str:
    if detector_id in DETECTOR_LABELS:
        return DETECTOR_LABELS[detector_id]
    return detector_id.replace("_", " ").title()


def flatten_results(results: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for detector_id, values in results.items():
        label = detector_label(detector_id)
        if isinstance(values, dict) and values.get("error"):
            rows.append(
                {
                    "detector": detector_id,
                    "Detector": label,
                    "alert": values["error"],
                    "details": {"error": values["error"]},
                }
            )
            continue

        try:
            iterator = iter(values)
        except TypeError:
            rows.append(
                {
                    "detector": detector_id,
                    "Detector": label,
                    "alert": str(values),
                    "details": {"value": values},
                }
            )
            continue

        for item in iterator:
            details = item if isinstance(item, dict) else {"value": item}
            rows.append(
                {
                    "detector": detector_id,
                    "Detector": label,
                    "alert": str(item),
                    "details": details,
                }
            )
    return rows


def available_detector_labels(rows: list[dict[str, Any]]) -> list[str]:
    labels = {row["Detector"] for row in rows}
    sorted_labels = sorted(
        labels, key=lambda label: (DETECTOR_ORDER.get(label, 99), label)
    )
    return [ALL_DETECTORS, *sorted_labels]


def filter_rows(
    rows: list[dict[str, Any]], selected_label: str
) -> list[dict[str, Any]]:
    if selected_label == ALL_DETECTORS:
        return rows
    return [row for row in rows if row["Detector"] == selected_label]


def build_raw_table(rows: list[dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(
        [{"Detector": row["Detector"], "Alert": row["alert"]} for row in rows],
        columns=["Detector", "Alert"],
    )


def build_normalized_tables(
    rows: list[dict[str, Any]],
) -> OrderedDict[str, pd.DataFrame]:
    grouped: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
    for row in sorted(
        rows,
        key=lambda item: (DETECTOR_ORDER.get(item["Detector"], 99), item["Detector"]),
    ):
        grouped.setdefault(row["Detector"], []).append(row)

    tables: OrderedDict[str, pd.DataFrame] = OrderedDict()
    for label, detector_rows in grouped.items():
        tables[label] = _build_normalized_table(label, detector_rows)
    return tables


def _build_normalized_table(label: str, rows: list[dict[str, Any]]) -> pd.DataFrame:
    if any("error" in row["details"] for row in rows):
        return pd.DataFrame(
            [{"Error": row["details"].get("error", row["alert"])} for row in rows],
            columns=["Error"],
        )
    if label == "Deauth":
        return pd.DataFrame(
            [
                {
                    "Attacker": row["details"].get("attacker"),
                    "Victim": row["details"].get("victim"),
                    "Frame Count": row["details"].get("count"),
                }
                for row in rows
            ],
            columns=["Attacker", "Victim", "Frame Count"],
        )
    if label == "Rogue AP":
        return pd.DataFrame(
            [
                {
                    "BSSID": row["details"].get("bssid"),
                    "SSID": row["details"].get("ssid"),
                }
                for row in rows
            ],
            columns=["BSSID", "SSID"],
        )
    if label == "Unknown Device":
        return pd.DataFrame(
            [
                {
                    "MAC Address": row["details"].get("mac"),
                    "Info": row["details"].get("info"),
                }
                for row in rows
            ],
            columns=["MAC Address", "Info"],
        )
    if label == "Weak Encryption":
        return pd.DataFrame(
            [
                {
                    "BSSID": row["details"].get("bssid"),
                    "SSID": row["details"].get("ssid"),
                    "Security": row["details"].get("security"),
                }
                for row in rows
            ],
            columns=["BSSID", "SSID", "Security"],
        )
    return pd.DataFrame([row["details"] for row in rows])

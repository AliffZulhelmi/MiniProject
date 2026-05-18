# Alert Table Normalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add detector filtering plus raw and detector-specific normalized alert tables to the Streamlit dashboard.

**Architecture:** Put pure alert table transformation code in `mini_wids/ui/alert_tables.py` and keep Streamlit rendering in `mini_wids/ui/app.py`. Detector outputs, storage payloads, and engine behavior remain unchanged. Tests cover the pure transformation layer so UI changes stay low-risk.

**Tech Stack:** Python, pandas, Streamlit, pytest, Mini WIDS detector result dictionaries.

---

## File Map

- Create `mini_wids/ui/alert_tables.py`: detector labels, result flattening, filtering, raw table generation, normalized table generation.
- Create `tests/ui/test_alert_tables.py`: pure unit tests for all new formatting behavior.
- Modify `mini_wids/ui/app.py`: add detector filter, table mode selector, labeled chart, raw table view, and separate normalized tables.

## Task 1: Alert Table Helper Tests

**Files:**
- Create: `tests/ui/test_alert_tables.py`
- Create later: `mini_wids/ui/alert_tables.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/ui/test_alert_tables.py`:

```python
# ruff: noqa: S101

from mini_wids.ui.alert_tables import (
    available_detector_labels,
    build_normalized_tables,
    build_raw_table,
    detector_label,
    filter_rows,
    flatten_results,
)


SAMPLE_RESULTS = {
    "deauth": [
        {"attacker": "aa:bb:cc:00:00:01", "victim": "aa:bb:cc:00:00:02", "count": 6}
    ],
    "rogue_ap": [
        {"bssid": "11:22:33:44:55:66", "ssid": "CafeLab-FreeWiFi"}
    ],
    "unknown_device": [
        {"mac": "22:33:44:55:66:77", "info": None}
    ],
    "weak_encryption": [
        {"bssid": "33:44:55:66:77:88", "ssid": "Guest", "security": "WPA-TKIP"}
    ],
}


def test_detector_label_uses_friendly_names():
    assert detector_label("deauth") == "Deauth"
    assert detector_label("rogue_ap") == "Rogue AP"
    assert detector_label("unknown_device") == "Unknown Device"
    assert detector_label("weak_encryption") == "Weak Encryption"
    assert detector_label("new_detector") == "New Detector"


def test_flatten_results_preserves_raw_details_and_labels():
    rows = flatten_results(SAMPLE_RESULTS)

    assert rows[0]["detector"] == "deauth"
    assert rows[0]["Detector"] == "Deauth"
    assert rows[0]["details"] == SAMPLE_RESULTS["deauth"][0]
    assert "attacker" in rows[0]["alert"]


def test_available_detector_labels_are_sorted_with_all_first():
    rows = flatten_results(SAMPLE_RESULTS)

    assert available_detector_labels(rows) == [
        "All Detectors",
        "Deauth",
        "Rogue AP",
        "Unknown Device",
        "Weak Encryption",
    ]


def test_filter_rows_by_friendly_detector_label():
    rows = flatten_results(SAMPLE_RESULTS)

    filtered = filter_rows(rows, "Rogue AP")

    assert len(filtered) == 1
    assert filtered[0]["detector"] == "rogue_ap"
    assert filter_rows(rows, "All Detectors") == rows


def test_build_raw_table_uses_display_columns():
    rows = flatten_results(SAMPLE_RESULTS)

    raw = build_raw_table(rows)

    assert list(raw.columns) == ["Detector", "Alert"]
    assert raw.iloc[1]["Detector"] == "Rogue AP"
    assert "CafeLab-FreeWiFi" in raw.iloc[1]["Alert"]


def test_build_normalized_tables_creates_separate_detector_tables():
    rows = flatten_results(SAMPLE_RESULTS)

    tables = build_normalized_tables(rows)

    assert list(tables) == ["Deauth", "Rogue AP", "Unknown Device", "Weak Encryption"]
    assert list(tables["Deauth"].columns) == ["Attacker", "Victim", "Frame Count"]
    assert list(tables["Rogue AP"].columns) == ["BSSID", "SSID"]
    assert list(tables["Unknown Device"].columns) == ["MAC Address", "Info"]
    assert list(tables["Weak Encryption"].columns) == ["BSSID", "SSID", "Security"]
    assert tables["Deauth"].iloc[0]["Frame Count"] == 6
    assert tables["Rogue AP"].iloc[0]["SSID"] == "CafeLab-FreeWiFi"


def test_error_results_are_displayable():
    rows = flatten_results({"rogue_ap": {"error": "adapter failed"}})

    raw = build_raw_table(rows)
    tables = build_normalized_tables(rows)

    assert raw.iloc[0]["Detector"] == "Rogue AP"
    assert "adapter failed" in raw.iloc[0]["Alert"]
    assert list(tables["Rogue AP"].columns) == ["Error"]
    assert tables["Rogue AP"].iloc[0]["Error"] == "adapter failed"
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
.venv/bin/python -m pytest tests/ui/test_alert_tables.py -q -s
```

Expected: FAIL during import because `mini_wids.ui.alert_tables` does not exist.

## Task 2: Alert Table Helper Implementation

**Files:**
- Create: `mini_wids/ui/alert_tables.py`
- Test: `tests/ui/test_alert_tables.py`

- [ ] **Step 1: Implement the helper module**

Create `mini_wids/ui/alert_tables.py`:

```python
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
    sorted_labels = sorted(labels, key=lambda label: (DETECTOR_ORDER.get(label, 99), label))
    return [ALL_DETECTORS, *sorted_labels]


def filter_rows(rows: list[dict[str, Any]], selected_label: str) -> list[dict[str, Any]]:
    if selected_label == ALL_DETECTORS:
        return rows
    return [row for row in rows if row["Detector"] == selected_label]


def build_raw_table(rows: list[dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame(
        [{"Detector": row["Detector"], "Alert": row["alert"]} for row in rows],
        columns=["Detector", "Alert"],
    )


def build_normalized_tables(rows: list[dict[str, Any]]) -> OrderedDict[str, pd.DataFrame]:
    grouped: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
    for row in sorted(rows, key=lambda item: (DETECTOR_ORDER.get(item["Detector"], 99), item["Detector"])):
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
                {"BSSID": row["details"].get("bssid"), "SSID": row["details"].get("ssid")}
                for row in rows
            ],
            columns=["BSSID", "SSID"],
        )
    if label == "Unknown Device":
        return pd.DataFrame(
            [
                {"MAC Address": row["details"].get("mac"), "Info": row["details"].get("info")}
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
```

- [ ] **Step 2: Run tests to verify GREEN**

Run:

```bash
.venv/bin/python -m pytest tests/ui/test_alert_tables.py -q -s
```

Expected: PASS.

## Task 3: Dashboard Integration

**Files:**
- Modify: `mini_wids/ui/app.py`
- Test: `tests/ui/test_alert_tables.py`

- [ ] **Step 1: Update dashboard imports**

Modify the top of `mini_wids/ui/app.py` to import the helper functions:

```python
from mini_wids.ui.alert_tables import (
    available_detector_labels,
    build_normalized_tables,
    build_raw_table,
    filter_rows,
    flatten_results,
)
```

- [ ] **Step 2: Replace inline flattening and table rendering**

Inside the block after `results = process_pcap(str(pcap_path))`, replace the current inline `rows = []` flattening and table display with:

```python
            rows = flatten_results(results)
            detector_options = available_detector_labels(rows)
            selected_detector = st.selectbox("Detector", detector_options)
            table_mode = st.radio("Table view", ["Raw", "Normalized"], horizontal=True)
            filtered_rows = filter_rows(rows, selected_detector)

            df = build_raw_table(filtered_rows)

            if not df.empty:
                counts = df.groupby("Detector").size().reset_index(name="count")
                fig = px.bar(
                    counts,
                    x="Detector",
                    y="count",
                    color="Detector",
                    title="Alerts by Detector",
                )
                st.plotly_chart(fig, use_container_width=True)

            st.subheader("Alerts")
            if not filtered_rows:
                st.info("No alerts match the selected detector.")
            elif table_mode == "Raw":
                st.dataframe(df.head(200))
            else:
                for detector, table in build_normalized_tables(filtered_rows).items():
                    st.markdown(f"#### {detector}")
                    st.dataframe(table.head(200))
```

- [ ] **Step 3: Keep save-to-DB raw**

Below the display block, keep save behavior based on `filtered_rows` raw details:

```python
            if st.button("Save alerts to DB"):
                flat = []
                for row in filtered_rows:
                    details = row.get("details")
                    entry = {
                        "detector": row.get("detector"),
                        **(details if isinstance(details, dict) else {"value": details}),
                    }
                    flat.append(entry)
                save_alerts(flat)
                st.success("Saved alerts")
```

- [ ] **Step 4: Run the full test suite**

Run:

```bash
.venv/bin/python -m pytest -q -s
```

Expected: PASS.

## Task 4: Manual Dashboard Verification

**Files:**
- Uses: `mini_wids/ui/app.py`
- Uses: `data/sample_pcaps/demo_capture.pcap`

- [ ] **Step 1: Generate a sample PCAP**

Run:

```bash
.venv/bin/python scripts/generate_sample_pcap.py
```

Expected output includes:

```text
Wrote demo pcap: data/sample_pcaps/demo_capture.pcap
Seed: 20260518
```

- [ ] **Step 2: Start the dashboard**

Run:

```bash
.venv/bin/streamlit run mini_wids/ui/app.py
```

Expected: Streamlit starts and shows a local URL.

- [ ] **Step 3: Verify UI behavior**

In the browser:

- Click `Process sample pcap`.
- Confirm the detector filter includes `All Detectors`, `Deauth`, `Rogue AP`, `Unknown Device`, and `Weak Encryption`.
- In `Raw` mode, confirm a single table appears with `Detector` and `Alert`.
- Switch to `Normalized` mode and confirm separate detector sections appear.
- Select `Rogue AP` and confirm only the `Rogue AP` chart/table remains.
- Select `Weak Encryption` and confirm columns are `BSSID`, `SSID`, and `Security`.

## Task 5: Commit

**Files:**
- `mini_wids/ui/alert_tables.py`
- `mini_wids/ui/app.py`
- `tests/ui/test_alert_tables.py`

- [ ] **Step 1: Check status**

Run:

```bash
git status --short
```

Expected: Only intended files are staged or unstaged for this feature, aside from known unrelated local edits.

- [ ] **Step 2: Stage intended files**

Run:

```bash
git add mini_wids/ui/alert_tables.py mini_wids/ui/app.py tests/ui/test_alert_tables.py
```

- [ ] **Step 3: Commit**

Run:

```bash
git commit -m "feat: add alert table filtering and normalization"
```

Expected: Commit succeeds.

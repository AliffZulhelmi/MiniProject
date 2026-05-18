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
    "rogue_ap": [{"bssid": "11:22:33:44:55:66", "ssid": "CafeLab-FreeWiFi"}],
    "unknown_device": [{"mac": "22:33:44:55:66:77", "info": None}],
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

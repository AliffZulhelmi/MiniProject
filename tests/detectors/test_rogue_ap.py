from mini_wids.detectors.rogue_ap import detect_rogue_aps, load_authorized_bssids


def test_detect_rogue_ap_with_authorized_list(tmp_path, monkeypatch):
    cfg = tmp_path / "authorized_aps.yml"
    cfg.write_text("""authorized_aps:\n  - bssid: "aa:bb:cc:dd:ee:ff"\n""")

    # point loader at tmp file
    bssids = load_authorized_bssids(str(cfg))
    assert "aa:bb:cc:dd:ee:ff" in bssids

    observed = [
        {"bssid": "aa:bb:cc:dd:ee:ff", "ssid": "Trusted"},
        {"bssid": "11:22:33:44:55:66", "ssid": "Rogue"},
    ]

    alerts = detect_rogue_aps(observed, authorized_bssids=bssids)
    assert len(alerts) == 1
    assert alerts[0]["bssid"] == "11:22:33:44:55:66"

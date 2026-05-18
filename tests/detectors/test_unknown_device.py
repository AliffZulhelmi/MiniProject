from mini_wids.detectors.unknown_device import detect_unknown_devices, load_authorized_macs


def test_unknown_device_detection(tmp_path):
    cfg = tmp_path / "authorized_devices.yml"
    cfg.write_text("""authorized_devices:\n  - mac: "aa:bb:cc:dd:ee:01"\n""")

    authorized = load_authorized_macs(str(cfg))
    observed = [{"mac": "aa:bb:cc:dd:ee:01"}, {"mac": "11:22:33:44:55:66"}]
    alerts = detect_unknown_devices(observed, authorized_macs=authorized)
    assert len(alerts) == 1
    assert alerts[0]["mac"] == "11:22:33:44:55:66"

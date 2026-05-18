from mini_wids.detectors.weak_encryption import detect_weak_encryption


def test_detect_weak_encryption():
    observed = [
        {"bssid": "aa:bb:cc:dd:ee:01", "ssid": "OldAP", "security": "WEP"},
        {"bssid": "11:22:33:44:55:66", "ssid": "NewAP", "security": "WPA2"},
    ]
    alerts = detect_weak_encryption(observed)
    assert len(alerts) == 1
    assert alerts[0]["bssid"] == "aa:bb:cc:dd:ee:01"

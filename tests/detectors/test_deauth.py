from mini_wids.detectors.deauth import detect_deauth


def make_pkt(src: str, dst: str, is_deauth: bool = True):
    return {"src": src, "dst": dst, "is_deauth": is_deauth}


def test_no_alert_below_threshold():
    packets = [make_pkt("aa:bb", "11:22") for _ in range(3)]
    alerts = detect_deauth(packets, threshold=5)
    assert alerts == []


def test_alert_when_threshold_exceeded():
    packets = [make_pkt("attacker:01", f"victim:{i}") for i in range(6)]
    alerts = detect_deauth(packets, threshold=5)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["attacker"] == "attacker:01"
    assert alert["count"] == 6
    assert alert["victim"] in {f"victim:{i}" for i in range(6)}

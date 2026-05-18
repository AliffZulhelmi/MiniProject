# ruff: noqa: S101

from mini_wids.detectors.unknown_device import detect_unknown_devices


def test_unknown_device_alerts_once_per_mac_and_keeps_info():
    observed = [
        {"mac": "6e:4d:a7:16:32:b7", "info": "Pixel-7"},
        {"mac": "6e:4d:a7:16:32:b7", "info": None},
        {"mac": "7e:08:8e:05:68:37", "info": "iPhone-13"},
    ]

    alerts = detect_unknown_devices(observed, authorized_macs=set())

    assert alerts == [
        {"mac": "6e:4d:a7:16:32:b7", "info": "Pixel-7"},
        {"mac": "7e:08:8e:05:68:37", "info": "iPhone-13"},
    ]

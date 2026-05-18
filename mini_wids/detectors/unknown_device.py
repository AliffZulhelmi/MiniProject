"""Unknown wireless device detector.

Flags devices by MAC when they are not listed in
`config/authorized_devices.yml`.
"""

from typing import Dict, Iterable, List, Optional

from mini_wids import config as mw_config


def detect_unknown_devices(
    observed: Iterable[Dict], authorized_macs: Optional[set] = None
) -> List[Dict]:
    if authorized_macs is None:
        authorized_macs = {m.lower() for m in mw_config.load_authorized_macs()}

    alerts_by_mac = {}
    for dev in observed:
        mac = (dev.get("mac") or dev.get("src") or "").lower()
        if not mac or mac in authorized_macs:
            continue

        info = dev.get("info")
        if mac not in alerts_by_mac:
            alerts_by_mac[mac] = {"mac": mac, "info": info}
        elif alerts_by_mac[mac].get("info") is None and info is not None:
            alerts_by_mac[mac]["info"] = info

    return list(alerts_by_mac.values())


def load_authorized_macs(path: Optional[str] = None) -> set:
    """Backward-compatible wrapper that returns a set of authorized MACs."""
    macs = mw_config.load_authorized_macs(path)
    return {m.lower() for m in macs}


def _device_info_from_packet(pkt, dot11_elt) -> str | None:
    if dot11_elt is None or not pkt.haslayer(dot11_elt):
        return None

    el = pkt.getlayer(dot11_elt)
    while el is not None:
        raw_info = getattr(el, "info", None)
        if raw_info:
            text = raw_info.decode("utf-8", errors="ignore")
            if text.startswith("device="):
                return text.split("=", 1)[1]
        if hasattr(el.payload, "getlayer"):
            el = el.payload.getlayer(dot11_elt)
        else:
            break
    return None


def detect_unknown_devices_from_scapy(packets, authorized_macs: Optional[set] = None):
    """Adapter: extract source MACs and optional demo device names."""
    try:
        from scapy.layers.dot11 import Dot11Elt  # type: ignore
    except Exception:
        Dot11Elt = None  # type: ignore

    def pkt_to_dev(pkt):
        if isinstance(pkt, dict):
            return pkt
        try:
            src = getattr(pkt, "addr2", None) or getattr(pkt, "src", None)
            info = _device_info_from_packet(pkt, Dot11Elt)
        except Exception:
            src = None
            info = None
        return {"mac": src, "info": info}

    devs = (pkt_to_dev(p) for p in packets)
    return detect_unknown_devices(devs, authorized_macs=authorized_macs)


__all__ = [
    "load_authorized_macs",
    "detect_unknown_devices",
    "detect_unknown_devices_from_scapy",
]

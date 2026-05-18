"""Rogue access point detector.

This detector flags observed AP beacons/probe responses whose BSSID is not
listed in `config/authorized_aps.yml`.

The module provides a lightweight, testable core function and a scapy
adapter for real packet streams.
"""

from typing import Dict, Iterable, List, Optional
from mini_wids import config as mw_config


def detect_rogue_aps(observed: Iterable[Dict], authorized_bssids: Optional[set] = None) -> List[Dict]:
    """Detect APs not found in `authorized_bssids`.

    observed: iterable of dicts with keys `bssid` and `ssid`.
    """
    if authorized_bssids is None:
        authorized_bssids = {b.lower() for b in mw_config.load_authorized_bssids()}

    alerts = []
    for ap in observed:
        bssid = (ap.get("bssid") or "").lower()
        ssid = ap.get("ssid")
        if not bssid:
            continue
        if bssid not in authorized_bssids:
            alerts.append({"bssid": bssid, "ssid": ssid})

    return alerts


def load_authorized_bssids(path: Optional[str] = None) -> set:
    """Backward-compatible wrapper that returns a set of authorized BSSIDs."""
    bssids = mw_config.load_authorized_bssids(path)
    return {b.lower() for b in bssids}



def detect_rogue_aps_from_scapy(packets, authorized_bssids: Optional[set] = None):
    """Adapter to extract AP info from scapy beacon/probe response packets."""
    try:
        from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt  # type: ignore
    except Exception:
        Dot11 = Dot11Beacon = Dot11ProbeResp = Dot11Elt = None  # type: ignore

    def pkt_to_ap(pkt):
        if isinstance(pkt, dict):
            return pkt
        try:
            # BSSID/address
            bssid = getattr(pkt, "addr3", None) or getattr(pkt, "addr2", None)
            ssid = None
            if Dot11Elt is not None and pkt.haslayer(Dot11Elt):
                # find SSID element (ID=0)
                el = pkt.getlayer(Dot11Elt)
                # walk linked Dot11Elt layers to find ID 0
                while el is not None:
                    if getattr(el, "ID", None) == 0:
                        ssid = el.info.decode("utf-8", errors="ignore") if getattr(el, "info", None) else None
                        break
                    el = el.payload.getlayer(Dot11Elt) if hasattr(el.payload, "getlayer") else None

            return {"bssid": bssid, "ssid": ssid}
        except Exception:
            return {"bssid": None, "ssid": None}

    aps = (pkt_to_ap(p) for p in packets)
    return detect_rogue_aps(aps, authorized_bssids=authorized_bssids)


__all__ = ["detect_rogue_aps", "detect_rogue_aps_from_scapy", "load_authorized_bssids"]
"""Rogue access point and evil twin detector entry point."""

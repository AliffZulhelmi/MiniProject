"""Normalize scapy packets into a small packet-event dict used by detectors.

This module provides a best-effort `normalize(pkt)` function that extracts
common fields like `src`, `dst`, `bssid`, `ssid`, `is_deauth`, and `security`.
"""

from typing import Dict, Any


def normalize(pkt) -> Dict[str, Any]:
    # Accept dict-like packets directly (useful in tests)
    if isinstance(pkt, dict):
        return pkt

    data = {"src": None, "dst": None, "bssid": None, "ssid": None, "is_deauth": False, "security": None}
    try:
        # common 802.11 addr fields
        data["src"] = getattr(pkt, "addr2", None) or getattr(pkt, "src", None)
        data["dst"] = getattr(pkt, "addr1", None) or getattr(pkt, "dst", None)
        data["bssid"] = getattr(pkt, "addr3", None)

        # deauth detection
        try:
            from scapy.layers.dot11 import Dot11Deauth, Dot11  # type: ignore

            if pkt.haslayer(Dot11Deauth):
                data["is_deauth"] = True
            else:
                if pkt.haslayer(Dot11):
                    dot11 = pkt.getlayer(Dot11)
                    if getattr(dot11, "type", None) == 0 and getattr(dot11, "subtype", None) == 12:
                        data["is_deauth"] = True
        except Exception:
            # scapy not present or layer introspection failed; skip
            pass

        # try to get SSID/security from Dot11Elt if available
        try:
            from scapy.layers.dot11 import Dot11Elt  # type: ignore

            if pkt.haslayer(Dot11Elt):
                el = pkt.getlayer(Dot11Elt)
                # walk elements
                while el is not None:
                    idv = getattr(el, "ID", None)
                    if idv == 0 and getattr(el, "info", None):
                        try:
                            data["ssid"] = el.info.decode("utf-8", errors="ignore")
                        except Exception:
                            data["ssid"] = str(el.info)
                    # security element heuristics
                    if getattr(el, "info", None):
                        try:
                            info = el.info.decode("utf-8", errors="ignore").lower()
                            if any(k in info for k in ("wep", "open", "tkip")):
                                data["security"] = info
                        except Exception:
                            pass
                    if hasattr(el.payload, "getlayer"):
                        el = el.payload.getlayer(Dot11Elt)
                    else:
                        break
        except Exception:
            pass
    except Exception:
        # keep default values on unexpected errors
        pass

    return data


__all__ = ["normalize"]
"""Packet normalization entry point."""

"""Weak wireless encryption detector.

Flags APs advertising weak or deprecated encryption (WEP, OPEN, TKIP).

Core functions operate on simple dicts; adapter provides best-effort
extraction from scapy packet objects but falls back to dict inputs for tests.
"""

from typing import Dict, Iterable, List, Optional


DEFAULT_INSECURE = {"wep", "open", "tkip"}


def detect_weak_encryption(observed: Iterable[Dict], insecure_signals: Optional[set] = None) -> List[Dict]:
	if insecure_signals is None:
		insecure_signals = DEFAULT_INSECURE

	alerts = []
	for ap in observed:
		sec = (ap.get("security") or "").lower()
		if not sec:
			continue
		for sig in insecure_signals:
			if sig in sec:
				alerts.append({"bssid": ap.get("bssid"), "ssid": ap.get("ssid"), "security": ap.get("security")})
				break
	return alerts


def detect_weak_encryption_from_scapy(packets, insecure_signals: Optional[set] = None):
	"""Best-effort adapter that extracts a `security` string from packet dicts or scapy objects."""
	try:
		from scapy.layers.dot11 import Dot11Elt  # type: ignore
	except Exception:
		Dot11Elt = None  # type: ignore

	def pkt_to_ap(pkt):
		if isinstance(pkt, dict):
			return pkt
		try:
			bssid = getattr(pkt, "addr3", None) or getattr(pkt, "addr2", None)
			ssid = None
			security = None
			if Dot11Elt is not None and pkt.haslayer(Dot11Elt):
				el = pkt.getlayer(Dot11Elt)
				# naive: if element info contains 'WEP' or similar, include it
				infos = []
				while el is not None:
					info = getattr(el, "info", None)
					if info:
						try:
							infos.append(info.decode("utf-8", errors="ignore"))
						except Exception:
							infos.append(str(info))
					# move to next Dot11Elt
					if hasattr(el.payload, "getlayer"):
						el = el.payload.getlayer(Dot11Elt)
					else:
						break
				joined = " ".join(infos).lower()
				security = joined
			return {"bssid": bssid, "ssid": ssid, "security": security}
		except Exception:
			return {"bssid": None, "ssid": None, "security": None}

	aps = (pkt_to_ap(p) for p in packets)
	return detect_weak_encryption(aps, insecure_signals=insecure_signals)


__all__ = ["detect_weak_encryption", "detect_weak_encryption_from_scapy"]


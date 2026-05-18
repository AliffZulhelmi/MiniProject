"""Unknown wireless device detector.

Flags devices (by MAC) that are not listed in `config/authorized_devices.yml`.

Produces a simple core function that accepts iterable dicts and a scapy
adapter for real packet streams.
"""

from typing import Dict, Iterable, List, Optional
from mini_wids import config as mw_config


def detect_unknown_devices(observed: Iterable[Dict], authorized_macs: Optional[set] = None) -> List[Dict]:
	if authorized_macs is None:
		authorized_macs = {m.lower() for m in mw_config.load_authorized_macs()}

	alerts = []
	for dev in observed:
		mac = (dev.get("mac") or dev.get("src") or "").lower()
		if not mac:
			continue
		if mac not in authorized_macs:
			alerts.append({"mac": mac, "info": dev.get("info")})
	return alerts


def load_authorized_macs(path: Optional[str] = None) -> set:
	"""Backward-compatible wrapper that returns a set of authorized MACs."""
	macs = mw_config.load_authorized_macs(path)
	return {m.lower() for m in macs}



def detect_unknown_devices_from_scapy(packets, authorized_macs: Optional[set] = None):
	"""Adapter: extract source MACs from scapy packets."""
	def pkt_to_dev(pkt):
		if isinstance(pkt, dict):
			return pkt
		try:
			src = getattr(pkt, "addr2", None) or getattr(pkt, "src", None)
		except Exception:
			src = None
		return {"mac": src}

	devs = (pkt_to_dev(p) for p in packets)
	return detect_unknown_devices(devs, authorized_macs=authorized_macs)


__all__ = ["load_authorized_macs", "detect_unknown_devices", "detect_unknown_devices_from_scapy"]


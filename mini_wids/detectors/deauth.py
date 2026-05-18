"""Deauthentication and disassociation attack detector.

This module provides a small, testable detector function that inspects a
sequence of simplified packet records and returns alerts when a source
transmits an excessive number of deauthentication frames.

The detector is intentionally KISS and modular: it operates on an abstract
list of packet-like dicts so it can be unit-tested without `scapy`.
"""

from collections import Counter
from typing import Dict, Iterable, List


def detect_deauth(packets: Iterable[Dict], threshold: int = 5) -> List[Dict]:
	"""Detect deauthentication floods.

	Args:
		packets: Iterable of packet-like dicts with at least the keys
			`is_deauth` (bool), `src` (str), and `dst` (str).
		threshold: Number of deauth frames from a single source required to
			raise an alert.

	Returns:
		A list of alert dicts. Each alert contains `attacker`, `count`, and
		an example `victim` address.
	"""

	src_counts = Counter()
	last_victim = {}

	for pkt in packets:
		try:
			if not pkt.get("is_deauth"):
				continue
			src = pkt.get("src")
			dst = pkt.get("dst")
		except AttributeError:
			# Non-dict packet-like objects are ignored in this simple detector
			continue

		if src is None:
			continue

		src_counts[src] += 1
		# remember a recent victim for context in alerts
		if dst:
			last_victim[src] = dst

	alerts = []
	for src, count in src_counts.items():
		if count >= threshold:
			alerts.append({"attacker": src, "count": count, "victim": last_victim.get(src)})

	return alerts


__all__ = ["detect_deauth"]


def detect_deauth_from_scapy(packets, threshold: int = 5):
	"""Adapter: accept an iterable of scapy packets and detect deauth floods.

	The adapter extracts the minimal fields required by `detect_deauth` so
	the core logic remains testable and independent of scapy types.
	"""
	try:
		# import scapy lazily to avoid hard dependency at module import time
		from scapy.layers.dot11 import Dot11Deauth, Dot11, Dot11Elt  # type: ignore
	except Exception:
		Dot11Deauth = None  # type: ignore

	def pkt_to_dict(pkt):
		# Support dict-like packets (for tests) directly
		if isinstance(pkt, dict):
			return pkt

		is_deauth = False
		src = None
		dst = None

		# Try to detect deauth frames
		try:
			if Dot11Deauth is not None and pkt.haslayer(Dot11Deauth):
				is_deauth = True
			else:
				# best-effort: check Dot11 type/subtype
				if pkt.haslayer(Dot11):
					dot11 = pkt.getlayer(Dot11)
					# management frames (type=0), deauth subtype commonly 12
					if getattr(dot11, "type", None) == 0 and getattr(dot11, "subtype", None) == 12:
						is_deauth = True

			# addresses
			src = getattr(pkt, "addr2", None) or getattr(pkt, "src", None)
			dst = getattr(pkt, "addr1", None) or getattr(pkt, "dst", None)
		except Exception:
			# be defensive and return a neutral dict
			return {"is_deauth": False, "src": None, "dst": None}

		return {"is_deauth": bool(is_deauth), "src": src, "dst": dst}

	mapped = (pkt_to_dict(p) for p in packets)
	return detect_deauth(mapped, threshold=threshold)


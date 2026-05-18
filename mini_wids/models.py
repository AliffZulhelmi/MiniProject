"""Shared domain models for packets, access points, devices, and alerts.

Small dataclasses used across the project to make data shapes explicit and
easy to serialize for storage or UI rendering.
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


@dataclass
class PacketEvent:
	src: Optional[str] = None
	dst: Optional[str] = None
	bssid: Optional[str] = None
	ssid: Optional[str] = None
	is_deauth: bool = False
	security: Optional[str] = None

	def to_dict(self) -> Dict[str, Any]:
		return asdict(self)


@dataclass
class AccessPoint:
	bssid: str
	ssid: Optional[str] = None
	security: Optional[str] = None
	channel: Optional[int] = None

	def to_dict(self) -> Dict[str, Any]:
		return asdict(self)


@dataclass
class Device:
	mac: str
	label: Optional[str] = None
	role: Optional[str] = None

	def to_dict(self) -> Dict[str, Any]:
		return asdict(self)


@dataclass
class Alert:
	detector: str
	payload: Dict[str, Any]
	ts: float

	def to_dict(self) -> Dict[str, Any]:
		return asdict(self)


"""Central configuration loader for Mini WIDS.

Provides small helpers that return lists/sets of authorized APs/devices.
Detectors and other modules should use these helpers instead of reading
YAML files themselves.
"""

from pathlib import Path
from typing import List, Dict, Any
import yaml


def _read_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def load_authorized_bssids(path: str | None = None) -> List[str]:
    cfg = _read_yaml(Path(path or "config/authorized_aps.yml"))
    entries = cfg.get("authorized_aps", [])
    return [e.get("bssid") for e in entries if e.get("bssid")]


def load_authorized_macs(path: str | None = None) -> List[str]:
    cfg = _read_yaml(Path(path or "config/authorized_devices.yml"))
    entries = cfg.get("authorized_devices", [])
    return [e.get("mac") for e in entries if e.get("mac")]


__all__ = ["load_authorized_bssids", "load_authorized_macs"]
"""Configuration loading entry point for Mini WIDS."""

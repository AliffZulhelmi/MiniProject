"""PCAP reader wrapper that centralizes reading PCAP/PCAPNG files.

Provides a thin wrapper around scapy.rdpcap to isolate direct scapy usage
for easier testing and mocking.
"""

from typing import Iterable


def read_pcap(path: str) -> Iterable:
    try:
        from scapy.all import rdpcap  # type: ignore
    except Exception:
        raise RuntimeError("scapy is required to read pcaps")

    return rdpcap(path)


__all__ = ["read_pcap"]
"""Wireshark PCAP and PCAPNG reader entry point."""

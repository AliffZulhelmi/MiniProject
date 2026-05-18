"""Live monitor-mode sniffer for Kali lab demonstrations.

This module intentionally enforces safety checks to avoid accidental misuse
against networks you do not own. By default it requires explicit confirmation
or an environment variable to enable live captures.
"""

from typing import Optional
from pathlib import Path
import os
import time
import re


def _is_monitor_interface(iface: str) -> bool:
    # conservative check: interface names commonly include 'mon' or start with 'wlan'
    return bool(re.search(r"(^wlan|mon)", iface))


def start_live_capture(interface: str, duration: int, out_path: str) -> str:
    """Start a short live capture using scapy and write to `out_path`.

    Safety checks:
    - interface name must look like a wireless/monitor interface
    - environment variable `MINI_WIDS_ALLOW_LIVE=1` OR user confirmation
      must be present before capture starts.

    Returns the path to the saved pcap file.
    """
    if not _is_monitor_interface(interface):
        raise ValueError("Refusing to capture on non-monitor interface: %s" % interface)

    allow = os.environ.get("MINI_WIDS_ALLOW_LIVE") == "1"
    if not allow:
        # interactive confirmation
        resp = input(f"Live capture will run on {interface} for {duration}s. Proceed? [y/N]: ")
        if resp.strip().lower() != "y":
            raise RuntimeError("Live capture aborted by user")

    try:
        from scapy.all import sniff, wrpcap  # type: ignore
    except Exception:
        raise RuntimeError("scapy is required for live capture")

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    print(f"Starting live capture on {interface} for {duration}s")
    pkts = sniff(iface=interface, timeout=duration)
    print(f"Captured {len(pkts)} packets; writing to {out}")
    wrpcap(str(out), pkts)
    return str(out)


def _cli():
    import argparse

    parser = argparse.ArgumentParser(description="Run a short live monitor-mode capture (use safely)")
    parser.add_argument("interface")
    parser.add_argument("--duration", type=int, default=15)
    parser.add_argument("--out", default="data/raw_pcaps/live_capture.pcap")
    args = parser.parse_args()

    try:
        p = start_live_capture(args.interface, args.duration, args.out)
        print("Wrote pcap:", p)
    except Exception as exc:
        print("Capture failed:", exc)


if __name__ == "__main__":
    _cli()
"""Kali Linux monitor-mode live sniffer entry point."""

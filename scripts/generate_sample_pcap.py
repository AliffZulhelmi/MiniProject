"""Generate deterministic, realistic-looking fake PCAPs for Mini WIDS demos.

Run this script to create `data/sample_pcaps/demo_capture.pcap`.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from mini_wids.sample_pcap_generator import (
    DEFAULT_OUTPUT,
    DEFAULT_SEED,
    FAKE_DEVICE_NAMES,
    FAKE_SSIDS,
    WEAK_SECURITY_MODES,
    build_demo_packets,
    build_demo_scenario,
    build_rng,
    choose_fake_device,
    choose_fake_ssid,
    choose_weak_security,
    make_association_request,
    make_beacon,
    make_deauth,
    random_mac,
    write_demo_pcap,
)

__all__ = [
    "DEFAULT_OUTPUT",
    "DEFAULT_SEED",
    "FAKE_DEVICE_NAMES",
    "FAKE_SSIDS",
    "WEAK_SECURITY_MODES",
    "build_demo_packets",
    "build_demo_scenario",
    "build_rng",
    "choose_fake_device",
    "choose_fake_ssid",
    "choose_weak_security",
    "make_association_request",
    "make_beacon",
    "make_deauth",
    "random_mac",
    "write_demo_pcap",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a realistic fake Mini WIDS demo PCAP"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help=f"Deterministic random seed (default: {DEFAULT_SEED})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output PCAP path (default: {DEFAULT_OUTPUT})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    pcap = write_demo_pcap(output=args.output, seed=args.seed)
    print(f"Wrote demo pcap: {pcap}")
    print(f"Seed: {args.seed}")


if __name__ == "__main__":
    main()

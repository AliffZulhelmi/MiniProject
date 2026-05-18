# Realistic PCAP Sample Generator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic fake-but-realistic demo PCAP generator that replaces obvious placeholder MACs, SSIDs, weak encryption, and client names.

**Architecture:** Keep `scripts/generate_sample_pcap.py` as the standalone entry point. Add small pure helper functions for seeded random choices and packet scenario construction, then keep `main()` responsible only for CLI parsing, directory creation, PCAP writing, and user output. Tests import the script module directly and verify behavior without depending on binary PCAP byte equality.

**Tech Stack:** Python, Scapy Dot11 packet layers, pytest, Mini WIDS `process_pcap()`.

---

## File Map

- Modify `scripts/generate_sample_pcap.py`: add deterministic fake profile helpers, realistic packet scenario builder, and `--seed` / `--output` CLI flags.
- Create `tests/scripts/test_generate_sample_pcap.py`: cover deterministic helper behavior, MAC validity, packet contents, and detector compatibility for generated PCAPs.
- Keep `config/*.yml` unchanged because config is authoritative and this feature only generates demo evidence.

## Task 1: Generator Behavior Tests

**Files:**
- Create: `tests/scripts/test_generate_sample_pcap.py`
- Modify: `scripts/generate_sample_pcap.py`

- [ ] **Step 1: Write failing tests for deterministic fake generation**

Create `tests/scripts/test_generate_sample_pcap.py` with:

```python
from pathlib import Path

from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Elt
from scapy.utils import wrpcap

from mini_wids.engine import process_pcap
from scripts import generate_sample_pcap as gen


def _ssid_values(packet):
    values = []
    element = packet.getlayer(Dot11Elt)
    while element is not None:
        if getattr(element, "ID", None) == 0 and getattr(element, "info", None):
            values.append(element.info.decode("utf-8", errors="ignore"))
        if hasattr(element.payload, "getlayer"):
            element = element.payload.getlayer(Dot11Elt)
        else:
            break
    return values


def _security_text(packet):
    values = []
    element = packet.getlayer(Dot11Elt)
    while element is not None:
        info = getattr(element, "info", None)
        if info:
            values.append(info.decode("utf-8", errors="ignore"))
        if hasattr(element.payload, "getlayer"):
            element = element.payload.getlayer(Dot11Elt)
        else:
            break
    return " ".join(values)


def test_random_mac_is_locally_administered_unicast_and_deterministic():
    first_rng = gen.build_rng(20260518)
    second_rng = gen.build_rng(20260518)

    first_mac = gen.random_mac(first_rng)
    second_mac = gen.random_mac(second_rng)

    first_octet = int(first_mac.split(":")[0], 16)
    assert first_mac == second_mac
    assert first_octet & 0b00000010
    assert not first_octet & 0b00000001
    assert first_mac != "aa:aa:aa:aa:aa:aa"


def test_build_demo_scenario_is_reproducible_and_realistic():
    first = gen.build_demo_scenario(seed=20260518)
    second = gen.build_demo_scenario(seed=20260518)

    assert first == second
    assert first.attacker.mac != "aa:aa:aa:aa:aa:aa"
    assert first.victim.mac != "11:11:11:11:11:11"
    assert first.attacker.name in gen.FAKE_DEVICE_NAMES
    assert first.victim.name in gen.FAKE_DEVICE_NAMES
    assert first.rogue_ap.ssid in gen.FAKE_SSIDS
    assert first.weak_ap.security in gen.WEAK_SECURITY_MODES
    assert first.authorized_ap.ssid == "MiniWIDS-Lab"
    assert first.authorized_ap.bssid == "00:11:22:33:44:55"


def test_build_demo_packets_contains_detector_friendly_wireless_events():
    packets = gen.build_demo_packets(seed=20260518)

    deauth_packets = [packet for packet in packets if packet.haslayer(Dot11Deauth)]
    beacons = [packet for packet in packets if packet.haslayer(Dot11) and packet.getlayer(Dot11).subtype == 8]
    ssids = [ssid for packet in beacons for ssid in _ssid_values(packet)]
    security_text = " ".join(_security_text(packet) for packet in beacons)

    assert len(deauth_packets) >= 6
    assert "MiniWIDS-Lab" in ssids
    assert any(ssid in gen.FAKE_SSIDS for ssid in ssids)
    assert any(mode.lower() in security_text.lower() for mode in gen.WEAK_SECURITY_MODES)


def test_generated_pcap_triggers_existing_detectors(tmp_path: Path):
    pcap_file = tmp_path / "demo_capture.pcap"
    packets = gen.build_demo_packets(seed=20260518)
    wrpcap(str(pcap_file), packets)

    results = process_pcap(str(pcap_file))
    scenario = gen.build_demo_scenario(seed=20260518)

    assert any(alert["attacker"] == scenario.attacker.mac for alert in results["deauth"])
    assert any(alert["bssid"] == scenario.rogue_ap.bssid for alert in results["rogue_ap"])
    assert any(alert["bssid"] == scenario.weak_ap.bssid for alert in results["weak_encryption"])
    assert any(alert["mac"] == scenario.attacker.mac for alert in results["unknown_device"])
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
pytest tests/scripts/test_generate_sample_pcap.py -q
```

Expected: FAIL because `build_rng`, `random_mac`, `build_demo_scenario`, constants, and `build_demo_packets(seed=...)` do not exist yet.

## Task 2: Deterministic Realistic Generator

**Files:**
- Modify: `scripts/generate_sample_pcap.py`
- Test: `tests/scripts/test_generate_sample_pcap.py`

- [ ] **Step 1: Implement the generator helpers and CLI**

Replace `scripts/generate_sample_pcap.py` with:

```python
"""Generate deterministic, realistic-looking fake PCAPs for Mini WIDS demos.

Run this script to create `data/sample_pcaps/demo_capture.pcap`.
"""

from __future__ import annotations

import argparse
import random
from dataclasses import dataclass
from pathlib import Path

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeReq, RadioTap
from scapy.utils import wrpcap

DEFAULT_SEED = 20260518
DEFAULT_OUTPUT = Path("data/sample_pcaps/demo_capture.pcap")

FAKE_DEVICE_NAMES = (
    "ThinkPad-T14",
    "MacBook-Air-M2",
    "iPhone-13",
    "Pixel-7",
    "Galaxy-A54",
    "iPad-Air",
    "HP-LaserJet",
    "Echo-Dot",
    "Chromecast-LivingRoom",
    "Nintendo-Switch",
)

FAKE_SSIDS = (
    "HomeHub-2G",
    "TP-Link_Guest",
    "CafeLab-FreeWiFi",
    "CampusDemo-IoT",
    "Netgear_Setup",
    "DLink-Guest",
    "FamilyRoom-WiFi",
    "Printer_Config",
)

WEAK_SECURITY_MODES = ("OPEN", "WEP", "WPA-TKIP")


@dataclass(frozen=True)
class FakeDevice:
    name: str
    mac: str


@dataclass(frozen=True)
class FakeAccessPoint:
    ssid: str
    bssid: str
    security: str
    channel: int


@dataclass(frozen=True)
class DemoScenario:
    attacker: FakeDevice
    victim: FakeDevice
    authorized_ap: FakeAccessPoint
    rogue_ap: FakeAccessPoint
    weak_ap: FakeAccessPoint


def build_rng(seed: int = DEFAULT_SEED) -> random.Random:
    return random.Random(seed)


def random_mac(rng: random.Random) -> str:
    octets = [rng.randrange(0, 256) for _ in range(6)]
    octets[0] = (octets[0] | 0b00000010) & 0b11111110
    return ":".join(f"{octet:02x}" for octet in octets)


def choose_fake_device(rng: random.Random) -> str:
    return rng.choice(FAKE_DEVICE_NAMES)


def choose_fake_ssid(rng: random.Random) -> str:
    return rng.choice(FAKE_SSIDS)


def choose_weak_security(rng: random.Random) -> str:
    return rng.choice(WEAK_SECURITY_MODES)


def _unique_mac(rng: random.Random, used: set[str]) -> str:
    mac = random_mac(rng)
    while mac in used:
        mac = random_mac(rng)
    used.add(mac)
    return mac


def build_demo_scenario(seed: int = DEFAULT_SEED) -> DemoScenario:
    rng = build_rng(seed)
    used_macs = {"00:11:22:33:44:55"}

    attacker = FakeDevice(name=choose_fake_device(rng), mac=_unique_mac(rng, used_macs))
    victim = FakeDevice(name=choose_fake_device(rng), mac=_unique_mac(rng, used_macs))

    authorized_ap = FakeAccessPoint(
        ssid="MiniWIDS-Lab",
        bssid="00:11:22:33:44:55",
        security="WPA2",
        channel=6,
    )
    rogue_ap = FakeAccessPoint(
        ssid=choose_fake_ssid(rng),
        bssid=_unique_mac(rng, used_macs),
        security=choose_weak_security(rng),
        channel=rng.choice((1, 6, 11)),
    )
    weak_ap = FakeAccessPoint(
        ssid=choose_fake_ssid(rng),
        bssid=_unique_mac(rng, used_macs),
        security=choose_weak_security(rng),
        channel=rng.choice((1, 6, 11)),
    )

    return DemoScenario(
        attacker=attacker,
        victim=victim,
        authorized_ap=authorized_ap,
        rogue_ap=rogue_ap,
        weak_ap=weak_ap,
    )


def make_deauth(src: str, dst: str):
    return RadioTap() / Dot11(addr1=dst, addr2=src, addr3=src) / Dot11Deauth()


def make_beacon(bssid: str, ssid: str, security: str | None = None, channel: int | None = None):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon(cap="ESS+privacy" if security and security != "OPEN" else "ESS")
    packet = RadioTap() / dot11 / beacon / Dot11Elt(ID=0, info=ssid.encode())
    if channel is not None:
        packet /= Dot11Elt(ID=3, info=bytes([channel]))
    if security:
        packet /= Dot11Elt(ID=221, info=security.encode())
    return packet


def make_probe_request(src: str, device_name: str, ssid: str):
    dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=src, addr3="ff:ff:ff:ff:ff:ff")
    return (
        RadioTap()
        / dot11
        / Dot11ProbeReq()
        / Dot11Elt(ID=0, info=ssid.encode())
        / Dot11Elt(ID=221, info=f"device={device_name}".encode())
    )


def build_demo_packets(seed: int = DEFAULT_SEED):
    scenario = build_demo_scenario(seed)
    packets = []

    for _ in range(6):
        packets.append(make_deauth(scenario.attacker.mac, scenario.victim.mac))

    packets.append(make_probe_request(scenario.attacker.mac, scenario.attacker.name, scenario.rogue_ap.ssid))
    packets.append(make_probe_request(scenario.victim.mac, scenario.victim.name, scenario.authorized_ap.ssid))
    packets.append(
        make_beacon(
            scenario.authorized_ap.bssid,
            scenario.authorized_ap.ssid,
            security=scenario.authorized_ap.security,
            channel=scenario.authorized_ap.channel,
        )
    )
    packets.append(
        make_beacon(
            scenario.rogue_ap.bssid,
            scenario.rogue_ap.ssid,
            security=scenario.rogue_ap.security,
            channel=scenario.rogue_ap.channel,
        )
    )
    packets.append(
        make_beacon(
            scenario.weak_ap.bssid,
            scenario.weak_ap.ssid,
            security=scenario.weak_ap.security,
            channel=scenario.weak_ap.channel,
        )
    )

    return packets


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a realistic fake Mini WIDS demo PCAP")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help=f"Deterministic random seed (default: {DEFAULT_SEED})")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help=f"Output PCAP path (default: {DEFAULT_OUTPUT})")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    packets = build_demo_packets(seed=args.seed)
    wrpcap(str(args.output), packets)
    print(f"Wrote demo pcap: {args.output}")
    print(f"Seed: {args.seed}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run tests to verify GREEN**

Run:

```bash
pytest tests/scripts/test_generate_sample_pcap.py -q
```

Expected: PASS.

## Task 3: Regression Verification

**Files:**
- Test: `tests/scripts/test_generate_sample_pcap.py`
- Test: `tests/test_integration_pcap.py`

- [ ] **Step 1: Run targeted generator and existing PCAP tests**

Run:

```bash
pytest tests/scripts/test_generate_sample_pcap.py tests/test_integration_pcap.py -q
```

Expected: PASS.

- [ ] **Step 2: Run the full test suite**

Run:

```bash
pytest -q
```

Expected: PASS or report existing unrelated failures with exact output.

- [ ] **Step 3: Run the generator CLI**

Run:

```bash
python scripts/generate_sample_pcap.py --output data/sample_pcaps/demo_capture.pcap
```

Expected output includes:

```text
Wrote demo pcap: data/sample_pcaps/demo_capture.pcap
Seed: 20260518
```

- [ ] **Step 4: Process the generated PCAP**

Run:

```bash
python -m mini_wids.engine data/sample_pcaps/demo_capture.pcap
```

Expected: JSON output includes non-empty `deauth`, `rogue_ap`, `unknown_device`, and `weak_encryption` result lists.

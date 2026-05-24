"""Generate deterministic, realistic-looking fake PCAPs for Mini WIDS demos."""

from __future__ import annotations

import logging
import os
import random
import time
from dataclasses import dataclass
from pathlib import Path

from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    RadioTap,
)
from scapy.utils import wrpcap

DEFAULT_SEED = 20260518
DEFAULT_OUTPUT = Path("data/sample_pcaps/demo_capture.pcap")
DEFAULT_DEAUTH_ALERTS = 45
DEFAULT_ROGUE_AP_ALERTS = 8
DEFAULT_WEAK_ENCRYPTION_ALERTS = 35
DEAUTH_FRAMES_PER_ATTACKER = 5
RANDOM_PREFIX = "random_capture"

ALERT_TYPE_SLUGS = {
    "deauth": "deauth",
    "rogue_ap": "rogue-ap",
    "weak_encryption": "weak-encryption",
    "unknown_device": "unknown-device",
}
AUTHORIZED_CLIENT_MACS = ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02")

ALERT_TYPE_PACKET_COUNTS = {
    "deauth": {
        "deauth_alerts": 30,
        "rogue_ap_alerts": 0,
        "weak_encryption_alerts": 0,
    },
    "rogue_ap": {
        "deauth_alerts": 0,
        "rogue_ap_alerts": 15,
        "weak_encryption_alerts": 0,
    },
    "weak_encryption": {
        "deauth_alerts": 0,
        "rogue_ap_alerts": 0,
        "weak_encryption_alerts": 30,
    },
}

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


@dataclass(frozen=True)
class GeneratedPcap:
    path: Path
    seed: int


def build_rng(seed: int = DEFAULT_SEED) -> random.Random:
    return random.Random(seed)  # noqa: S311 - deterministic fake demo data only


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


def random_demo_seed() -> int:
    """Return a cryptographically random 32-bit seed for each generation call."""
    try:
        return int.from_bytes(os.urandom(4), "big")
    except OSError:
        logging.getLogger(__name__).warning(
            "os.urandom unavailable; falling back to time-based seed"
        )
        return time.time_ns() % (2**32)


def next_demo_pcap_path(
    output_dir: str | Path = DEFAULT_OUTPUT.parent,
    prefix: str = RANDOM_PREFIX,
    suffix: str = ".pcap",
) -> Path:
    """Return the next 4-digit numbered PCAP path for a safe filename prefix."""
    prefix = prefix.strip()
    if not prefix or "/" in prefix or "\\" in prefix:
        raise ValueError(f"Invalid pcap prefix: {prefix!r}")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    for index in range(1, 10000):
        candidate = output_path / f"{prefix}_{index:04d}{suffix}"
        if not candidate.exists():
            return candidate

    raise RuntimeError(f"Exhausted 9999 pcap slots for prefix {prefix!r}")


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


def make_deauth(src: str, dst: str, bssid: str | None = None):
    return RadioTap() / Dot11(addr1=dst, addr2=src, addr3=bssid or src) / Dot11Deauth()


def make_beacon(
    bssid: str,
    ssid: str,
    security: str | None = None,
    channel: int | None = None,
    transmitter: str | None = None,
):
    dot11 = Dot11(
        type=0,
        subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=transmitter or bssid,
        addr3=bssid,
    )
    beacon = Dot11Beacon(
        cap="ESS+privacy" if security and security != "OPEN" else "ESS"
    )
    packet = RadioTap() / dot11 / beacon / Dot11Elt(ID=0, info=ssid.encode())
    if channel is not None:
        packet /= Dot11Elt(ID=3, info=bytes([channel]))
    if security:
        packet /= Dot11Elt(ID=221, info=security.encode())
    return packet


def make_association_request(src: str, bssid: str, device_name: str, ssid: str):
    dot11 = Dot11(
        type=0,
        subtype=0,
        addr1=bssid,
        addr2=src,
        addr3=bssid,
    )
    return (
        RadioTap()
        / dot11
        / Dot11AssoReq()
        / Dot11Elt(ID=0, info=ssid.encode())
        / Dot11Elt(ID=221, info=f"device={device_name}".encode())
    )


def build_demo_packets(
    seed: int = DEFAULT_SEED,
    deauth_alerts: int = DEFAULT_DEAUTH_ALERTS,
    rogue_ap_alerts: int = DEFAULT_ROGUE_AP_ALERTS,
    weak_encryption_alerts: int = DEFAULT_WEAK_ENCRYPTION_ALERTS,
):
    scenario = build_demo_scenario(seed)
    rng = build_rng(seed + 1)
    used_macs = {
        scenario.attacker.mac,
        scenario.victim.mac,
        scenario.authorized_ap.bssid,
        "AA:BB:CC:DD:EE:01".lower(),
        "AA:BB:CC:DD:EE:02".lower(),
    }
    packets = []

    packets.append(
        make_beacon(
            scenario.authorized_ap.bssid,
            scenario.authorized_ap.ssid,
            security=scenario.authorized_ap.security,
            channel=scenario.authorized_ap.channel,
        )
    )
    packets.append(
        make_association_request(
            scenario.attacker.mac,
            scenario.authorized_ap.bssid,
            scenario.attacker.name,
            scenario.rogue_ap.ssid,
        )
    )
    packets.append(
        make_association_request(
            scenario.victim.mac,
            scenario.authorized_ap.bssid,
            scenario.victim.name,
            scenario.authorized_ap.ssid,
        )
    )
    for _ in range(DEAUTH_FRAMES_PER_ATTACKER):
        packets.append(
            make_deauth(
                scenario.attacker.mac,
                scenario.victim.mac,
                bssid=scenario.authorized_ap.bssid,
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

    for _ in range(deauth_alerts):
        attacker = FakeDevice(
            name=choose_fake_device(rng),
            mac=_unique_mac(rng, used_macs),
        )
        packets.append(
            make_association_request(
                attacker.mac,
                scenario.authorized_ap.bssid,
                attacker.name,
                scenario.authorized_ap.ssid,
            )
        )
        for _ in range(DEAUTH_FRAMES_PER_ATTACKER):
            packets.append(
                make_deauth(
                    attacker.mac,
                    scenario.victim.mac,
                    bssid=scenario.authorized_ap.bssid,
                )
            )

    for _ in range(rogue_ap_alerts):
        rogue_ap = FakeAccessPoint(
            ssid=choose_fake_ssid(rng),
            bssid=_unique_mac(rng, used_macs),
            security="WPA2",
            channel=rng.choice((1, 6, 11)),
        )
        packets.append(
            make_beacon(
                rogue_ap.bssid,
                rogue_ap.ssid,
                security=rogue_ap.security,
                channel=rogue_ap.channel,
            )
        )

    for _ in range(weak_encryption_alerts):
        packets.append(
            make_beacon(
                scenario.authorized_ap.bssid,
                choose_fake_ssid(rng),
                security=choose_weak_security(rng),
                channel=scenario.authorized_ap.channel,
            )
        )

    return packets


def build_alert_type_packets(alert_type: str, seed: int = DEFAULT_SEED) -> list:
    """Build packets for a single alert-type sample PCAP."""
    normalized_alert_type = alert_type.strip().lower()
    if normalized_alert_type not in ALERT_TYPE_SLUGS:
        raise ValueError(
            f"Unknown alert_type {normalized_alert_type!r}. "
            f"Valid options: {sorted(ALERT_TYPE_SLUGS)}"
        )

    if normalized_alert_type == "unknown_device":
        return _build_unknown_device_packets(seed)
    if normalized_alert_type == "deauth":
        return _build_deauth_packets(seed)
    if normalized_alert_type == "rogue_ap":
        return _build_rogue_ap_packets(seed)
    return _build_weak_encryption_packets(seed)


def _build_deauth_packets(seed: int) -> list:
    """Generate only deauth frames from known lab clients."""
    scenario = build_demo_scenario(seed)
    source, victim = AUTHORIZED_CLIENT_MACS
    return [
        make_deauth(source, victim, bssid=scenario.authorized_ap.bssid)
        for _ in range(ALERT_TYPE_PACKET_COUNTS["deauth"]["deauth_alerts"])
    ]


def _build_rogue_ap_packets(seed: int) -> list:
    """Generate unknown AP beacons without weak security or unknown clients."""
    scenario = build_demo_scenario(seed)
    rng = build_rng(seed + 1)
    used_macs = {scenario.authorized_ap.bssid}
    transmitter = AUTHORIZED_CLIENT_MACS[0]
    packets = []

    for _ in range(ALERT_TYPE_PACKET_COUNTS["rogue_ap"]["rogue_ap_alerts"]):
        packets.append(
            make_beacon(
                _unique_mac(rng, used_macs),
                choose_fake_ssid(rng),
                security="WPA2",
                channel=rng.choice((1, 6, 11)),
                transmitter=transmitter,
            )
        )

    return packets


def _build_weak_encryption_packets(seed: int) -> list:
    """Generate weak-security beacons on the authorized lab AP."""
    scenario = build_demo_scenario(seed)
    rng = build_rng(seed + 1)
    transmitter = AUTHORIZED_CLIENT_MACS[0]
    packets = []

    for _ in range(
        ALERT_TYPE_PACKET_COUNTS["weak_encryption"]["weak_encryption_alerts"]
    ):
        packets.append(
            make_beacon(
                scenario.authorized_ap.bssid,
                choose_fake_ssid(rng),
                security=choose_weak_security(rng),
                channel=scenario.authorized_ap.channel,
                transmitter=transmitter,
            )
        )

    return packets


def _build_unknown_device_packets(seed: int) -> list:
    """Generate association requests from MACs outside the authorized whitelist."""
    scenario = build_demo_scenario(seed)
    rng = build_rng(seed + 1)
    used_macs = {
        *AUTHORIZED_CLIENT_MACS,
        scenario.authorized_ap.bssid,
        scenario.attacker.mac,
    }
    packets = []

    for _ in range(20):
        unknown = FakeDevice(
            name=choose_fake_device(rng),
            mac=_unique_mac(rng, used_macs),
        )
        packets.append(
            make_association_request(
                unknown.mac,
                scenario.authorized_ap.bssid,
                unknown.name,
                scenario.authorized_ap.ssid,
            )
        )

    return packets


def write_demo_pcap(
    output: str | Path = DEFAULT_OUTPUT,
    seed: int = DEFAULT_SEED,
) -> Path:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), build_demo_packets(seed=seed))
    return output_path


def write_numbered_demo_pcap(
    output_dir: str | Path = DEFAULT_OUTPUT.parent,
    seed: int | None = None,
) -> GeneratedPcap:
    chosen_seed = random_demo_seed() if seed is None else int(seed)
    output_path = next_demo_pcap_path(output_dir, prefix=RANDOM_PREFIX)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), build_demo_packets(seed=chosen_seed))
    return GeneratedPcap(path=output_path, seed=chosen_seed)


def write_alert_type_pcap(
    alert_type: str,
    output_dir: str | Path = DEFAULT_OUTPUT.parent,
    seed: int | None = None,
) -> GeneratedPcap:
    """Generate and save a PCAP containing frames for one alert type."""
    normalized_alert_type = alert_type.strip().lower()
    if normalized_alert_type not in ALERT_TYPE_SLUGS:
        raise ValueError(f"Unknown alert_type: {normalized_alert_type!r}")

    chosen_seed = random_demo_seed() if seed is None else int(seed)
    slug = ALERT_TYPE_SLUGS[normalized_alert_type]
    output_path = next_demo_pcap_path(output_dir, prefix=f"{slug}_capture")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(
        str(output_path),
        build_alert_type_packets(normalized_alert_type, seed=chosen_seed),
    )
    return GeneratedPcap(path=output_path, seed=chosen_seed)

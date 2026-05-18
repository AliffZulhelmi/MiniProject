"""Generate deterministic, realistic-looking fake PCAPs for Mini WIDS demos."""

from __future__ import annotations

import random
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
):
    dot11 = Dot11(
        type=0,
        subtype=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=bssid,
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


def build_demo_packets(seed: int = DEFAULT_SEED):
    scenario = build_demo_scenario(seed)
    packets = []

    for _ in range(6):
        packets.append(
            make_deauth(
                scenario.attacker.mac,
                scenario.victim.mac,
                bssid=scenario.authorized_ap.bssid,
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


def write_demo_pcap(
    output: str | Path = DEFAULT_OUTPUT,
    seed: int = DEFAULT_SEED,
) -> Path:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), build_demo_packets(seed=seed))
    return output_path

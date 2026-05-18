# ruff: noqa: S101

from pathlib import Path

from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Elt
from scapy.utils import wrpcap

from mini_wids import sample_pcap_generator as gen
from mini_wids.engine import process_pcap


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
    scenario = gen.build_demo_scenario(seed=20260518)

    deauth_packets = [packet for packet in packets if packet.haslayer(Dot11Deauth)]
    beacons = [
        packet
        for packet in packets
        if packet.haslayer(Dot11) and packet.getlayer(Dot11).subtype == 8
    ]
    ssids = [ssid for packet in beacons for ssid in _ssid_values(packet)]
    packet_text = " ".join(_security_text(packet) for packet in packets)

    assert len(deauth_packets) >= 6
    assert "MiniWIDS-Lab" in ssids
    assert any(ssid in gen.FAKE_SSIDS for ssid in ssids)
    assert any(mode.lower() in packet_text.lower() for mode in gen.WEAK_SECURITY_MODES)
    assert f"device={scenario.attacker.name}" in packet_text
    assert f"device={scenario.victim.name}" in packet_text


def test_generated_pcap_triggers_existing_detectors(tmp_path: Path):
    pcap_file = tmp_path / "demo_capture.pcap"
    packets = gen.build_demo_packets(seed=20260518)
    wrpcap(str(pcap_file), packets)

    results = process_pcap(str(pcap_file))
    scenario = gen.build_demo_scenario(seed=20260518)

    assert any(
        alert["attacker"] == scenario.attacker.mac for alert in results["deauth"]
    )
    assert any(
        alert["bssid"] == scenario.rogue_ap.bssid for alert in results["rogue_ap"]
    )
    assert any(
        alert["bssid"] == scenario.weak_ap.bssid for alert in results["weak_encryption"]
    )
    assert any(
        alert["mac"] == scenario.attacker.mac for alert in results["unknown_device"]
    )

    rogue_bssids = {alert["bssid"] for alert in results["rogue_ap"]}
    assert "ff:ff:ff:ff:ff:ff" not in rogue_bssids
    assert scenario.attacker.mac not in rogue_bssids
    assert scenario.victim.mac not in rogue_bssids


def test_write_demo_pcap_creates_processable_file(tmp_path: Path):
    pcap_file = tmp_path / "dashboard_sample.pcap"

    written = gen.write_demo_pcap(output=pcap_file, seed=20260518)
    results = process_pcap(str(written))

    assert written == pcap_file
    assert pcap_file.exists()
    assert results["deauth"]
    assert results["rogue_ap"]
    assert results["weak_encryption"]

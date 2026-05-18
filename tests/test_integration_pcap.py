import os

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt
from scapy.utils import wrpcap

from mini_wids.engine import process_pcap


def make_deauth(src, dst):
    pkt = RadioTap() / Dot11(addr1=dst, addr2=src, addr3=src) / Dot11Deauth()
    return pkt


def make_beacon(bssid, ssid, security=None):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon()
    ssid_el = Dot11Elt(ID=0, info=ssid.encode())
    # include a simple security element payload if provided
    if security:
        sec_el = Dot11Elt(ID=221, info=security.encode())
        pkt = RadioTap() / dot11 / beacon / ssid_el / sec_el
    else:
        pkt = RadioTap() / dot11 / beacon / ssid_el
    return pkt


def test_process_pcap_integration(tmp_path):
    # create temporary pcap with:
    # - multiple deauth frames from attacker to victim
    # - one beacon for authorized AP (matches config)
    # - one beacon for rogue AP

    attacker = "aa:aa:aa:aa:aa:aa"
    victim = "11:11:11:11:11:11"
    bssid_authorized = "00:11:22:33:44:55"  # present in config/authorized_aps.yml
    bssid_rogue = "66:55:44:33:22:11"

    packets = []
    # add 6 deauth frames to exceed default threshold (5)
    for _ in range(6):
        packets.append(make_deauth(attacker, victim))

    # authorized AP beacon
    packets.append(make_beacon(bssid_authorized, "MiniWIDS-Lab", security="WPA2"))
    # rogue AP beacon advertising 'OPEN' security
    packets.append(make_beacon(bssid_rogue, "RogueNet", security="OPEN"))

    pcap_file = tmp_path / "test_capture.pcap"
    wrpcap(str(pcap_file), packets)

    results = process_pcap(str(pcap_file))

    # deauth detector should report the attacker
    deauth_alerts = results.get("deauth", [])
    assert any(a["attacker"] == attacker for a in deauth_alerts)

    # rogue_ap detector should report the rogue bssid
    rogue_alerts = results.get("rogue_ap", [])
    assert any(a["bssid"] == bssid_rogue for a in rogue_alerts)

    # weak_encryption should report the OPEN AP
    weak_alerts = results.get("weak_encryption", [])
    assert any(a["bssid"] == bssid_rogue for a in weak_alerts)

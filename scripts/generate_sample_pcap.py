"""Generate small sample PCAPs for demos using scapy.

Run this script to create `data/sample_pcaps/demo_capture.pcap`.
"""

from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt
from scapy.utils import wrpcap
from pathlib import Path


def make_deauth(src, dst):
    return RadioTap() / Dot11(addr1=dst, addr2=src, addr3=src) / Dot11Deauth()


def make_beacon(bssid, ssid, security=None):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon()
    ssid_el = Dot11Elt(ID=0, info=ssid.encode())
    if security:
        sec_el = Dot11Elt(ID=221, info=security.encode())
        pkt = RadioTap() / dot11 / beacon / ssid_el / sec_el
    else:
        pkt = RadioTap() / dot11 / beacon / ssid_el
    return pkt


def main():
    out = Path("data/sample_pcaps")
    out.mkdir(parents=True, exist_ok=True)
    pcap = out / "demo_capture.pcap"

    attacker = "aa:aa:aa:aa:aa:aa"
    victim = "11:11:11:11:11:11"
    bssid_authorized = "00:11:22:33:44:55"
    bssid_rogue = "66:55:44:33:22:11"

    packets = []
    for _ in range(6):
        packets.append(make_deauth(attacker, victim))

    packets.append(make_beacon(bssid_authorized, "MiniWIDS-Lab", security="WPA2"))
    packets.append(make_beacon(bssid_rogue, "RogueNet", security="OPEN"))

    wrpcap(str(pcap), packets)
    print("Wrote demo pcap:", pcap)


if __name__ == "__main__":
    main()

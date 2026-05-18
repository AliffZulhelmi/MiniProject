# Kali Linux Lab Scripts

These scripts are for an owned lab router and owned test devices only.

Suggested workflow:

1. Put the wireless adapter into monitor mode on Kali Linux.
2. Capture traffic with Wireshark or `tshark`.
3. Save the capture into `data/raw_pcaps/`.
4. Run Mini WIDS in PCAP Analysis Mode.
5. Compare Mini WIDS alerts with Wireshark packet evidence.

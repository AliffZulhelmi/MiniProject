# Kali Linux Lab Guide

## Lab Boundary

Use only your own router, your own devices, and your own wireless adapter. Keep the lab SSID separate from public, campus, or neighbor networks.

## Required Kali Role

Kali Linux is used for:

- Monitor-mode packet capture
- Wireshark or `tshark` capture collection
- Controlled attack simulation against the lab router
- Validation that Mini WIDS alerts match packet evidence

## Suggested Capture Commands

List wireless interfaces:

```bash
iw dev
```

Start monitor mode with common Kali tooling:

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

Capture with Wireshark:

```bash
wireshark
```

Capture with `tshark`:

```bash
scripts/kali/capture_with_tshark.sh wlan0mon data/raw_pcaps/lab_capture.pcapng
```

## Demo Evidence

For each test scenario, capture:

- Screenshot of Kali or Wireshark showing relevant packets
- Mini WIDS dashboard alert screenshot
- Exported Mini WIDS alert log
- Short explanation of mitigation

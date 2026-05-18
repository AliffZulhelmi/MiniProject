# Realistic PCAP Sample Generator Design

## Purpose

Improve the existing demo PCAP generator so it creates lecturer-safe, realistic-looking fake wireless traffic instead of obvious placeholder values. The generated capture must remain reproducible by default so tests, demos, and screenshots stay stable.

## Scope

Modify `scripts/generate_sample_pcap.py` to keep producing `data/sample_pcaps/demo_capture.pcap`, while replacing hardcoded placeholder values with deterministic fake profiles. The generator will not capture real traffic, use real user device identifiers, or modify `config/*.yml`.

## Behavior

- Use a fixed default seed, with an optional CLI `--seed` override.
- Generate valid locally administered unicast MAC addresses for fake clients and rogue APs.
- Keep the authorized AP beacon aligned with `config/authorized_aps.yml`: SSID `MiniWIDS-Lab`, BSSID `00:11:22:33:44:55`, and security `WPA2`.
- Generate realistic fake client names from a small built-in catalog such as phones, laptops, tablets, printers, and IoT devices.
- Generate realistic fake SSIDs from a small built-in catalog such as home router names, guest networks, cafe-style names, and lab networks.
- Generate weak AP security from realistic weak modes: `OPEN`, `WEP`, and `WPA-TKIP`.
- Preserve current detector coverage by including a deauth burst, the authorized AP beacon, a rogue AP beacon, and at least one weak-encryption AP beacon.

## Architecture

The generator will stay as a standalone script. Small pure helper functions will own deterministic profile creation:

- `build_rng(seed)` returns an isolated `random.Random` instance.
- `random_mac(rng)` creates valid locally administered unicast MAC addresses.
- `choose_fake_device(rng)` selects a realistic fake device label.
- `choose_fake_ssid(rng)` selects a realistic fake SSID.
- `choose_weak_security(rng)` selects a weak security string recognized by the current detector adapter.
- `build_demo_packets(seed)` returns the Scapy packet list used by `main()`.

Packet-building helpers such as `make_deauth()` and `make_beacon()` will remain small and direct. The detector-facing `Dot11Elt` security payload will stay compatible with the existing weak-encryption adapter.

## CLI

The default command remains:

```bash
python scripts/generate_sample_pcap.py
```

Optional arguments:

```bash
python scripts/generate_sample_pcap.py --seed 1234 --output data/sample_pcaps/demo_capture.pcap
```

## Testing

Tests will focus on behavior rather than binary PCAP contents:

- The same seed produces identical fake profiles and packet summaries.
- Generated MAC addresses are locally administered unicast addresses.
- The default packet set still contains enough deauth frames to trigger the deauth detector.
- The default packet set still contains authorized, rogue, and weak-encryption beacons.
- The generated PCAP can be processed by `process_pcap()` and still triggers the expected detector families.

## Safety

All generated values are fake. MAC addresses will use locally administered addresses, and device names/SSIDs will be generic examples rather than real identifiers. The script must not read nearby networks, sniff packets, or generate traffic on the air.

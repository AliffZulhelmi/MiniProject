# Mini WIDS Dashboard Design

## Objective

Build a Python-based wireless intrusion detection dashboard that detects and logs rogue access points, deauthentication attacks, unknown devices, and weak wireless encryption using Wireshark evidence and Kali Linux lab captures.

## Required Technologies

| Technology | Usage |
| --- | --- |
| Python | Detection engine, models, packet normalization, storage, reporting |
| Wireshark | Packet capture, PCAP evidence, validation screenshots |
| Kali Linux | Monitor-mode capture environment and controlled wireless security lab |
| User Interface | Streamlit dashboard for alerts, AP inventory, device list, charts, exports |

## Main Modes

### PCAP Analysis Mode

The user selects a Wireshark `.pcap` or `.pcapng` file. Mini WIDS parses packets, normalizes wireless fields, runs detection rules, saves alerts, and shows results in the dashboard.

### Live Monitor Mode

The user runs the system on Kali Linux with a monitor-mode wireless adapter. Mini WIDS sniffs packets from the selected interface, runs the same detection rules, and updates the dashboard/logs.

## Detection Scope

### Deauthentication and Disassociation Attack Detection

Detect repeated management frames that can indicate a denial-of-service attack against wireless clients. The rule uses a time window and packet threshold from `config/rules.yml`.

### Rogue AP and Evil Twin Detection

Detect a known SSID advertised by an unknown BSSID, or a known SSID appearing with weaker security than the authorized AP configuration.

### Unknown Device Detection

Detect source or destination MAC addresses that appear in wireless activity but are not listed in `config/authorized_devices.yml`.

### Weak Encryption Detection

Flag access points advertising OPEN or WEP security as high severity. Flag WPA as medium severity when the lab policy expects WPA2 or WPA3.

## Evidence Logging

Every alert is saved with:

- timestamp
- attack type
- severity
- SSID
- BSSID or MAC address
- channel
- packet count
- source PCAP or interface
- recommendation

## Dashboard Views

- Overview metrics
- Live alerts table
- Access point inventory
- Unknown devices
- Attack timeline
- Evidence export

## Testing Strategy

Use repeatable unit tests for every detector and storage module. Use curated sample PCAPs for integration tests. Use Kali Linux and Wireshark screenshots for final validation evidence.

# Mini WIDS Project Structure

## Purpose

This structure separates the Mini WIDS project into small units so each part can be developed, tested, and explained during the presentation.

## Top-Level Files

| Path | Responsibility |
| --- | --- |
| `README.md` | Project overview, required technology mapping, setup commands |
| `requirements.txt` | Python libraries for Streamlit UI, Scapy packet parsing, data handling, and tests |
| `pyproject.toml` | Python project metadata and pytest configuration |
| `config/` | Whitelists and detection thresholds used by the engine |
| `data/` | PCAP evidence, logs, generated exports, and sample captures |
| `docs/` | Report support, implementation plan, diagrams, Kali guide, Wireshark workflow |
| `scripts/kali/` | Kali Linux capture helpers and lab commands |
| `mini_wids/` | Python application package |
| `tests/` | Automated tests for detectors, capture parsing, storage, reports, and UI helpers |

## Python Package Layout

| Path | Responsibility |
| --- | --- |
| `mini_wids/models.py` | Shared dataclasses such as `PacketEvent`, `AccessPoint`, `Device`, and `Alert` |
| `mini_wids/config.py` | YAML configuration loader for authorized APs, devices, and rules |
| `mini_wids/capture/pcap_reader.py` | Read Wireshark `.pcap` and `.pcapng` files |
| `mini_wids/capture/live_sniffer.py` | Sniff packets from a Kali Linux monitor-mode interface |
| `mini_wids/capture/normalizer.py` | Convert Scapy packets into simple `PacketEvent` records |
| `mini_wids/detectors/deauth.py` | Detect deauthentication and disassociation floods |
| `mini_wids/detectors/rogue_ap.py` | Detect evil twin or rogue AP behavior |
| `mini_wids/detectors/unknown_device.py` | Detect devices not listed in `config/authorized_devices.yml` |
| `mini_wids/detectors/weak_encryption.py` | Flag OPEN, WEP, and warning-level WPA networks |
| `mini_wids/storage/repository.py` | Save and query alerts in SQLite, export CSV evidence |
| `mini_wids/reporting/report_builder.py` | Build the final evidence report from stored alerts |
| `mini_wids/ui/app.py` | Streamlit dashboard entry point |

## Data Folders

| Path | Usage |
| --- | --- |
| `data/sample_pcaps/` | Small cleaned PCAPs for repeatable demos |
| `data/raw_pcaps/` | Raw lab captures from Wireshark or `tshark` |
| `data/logs/` | Runtime logs |
| `data/evidence/` | Screenshots and lecturer demo evidence |
| `data/exports/` | CSV, HTML, and PDF-style report exports |

## Implementation Order

1. Domain models and configuration loading
2. PCAP reading and packet normalization
3. Deauth detector
4. AP inventory and weak encryption detector
5. Rogue AP detector
6. Unknown device detector
7. SQLite evidence logger and CSV export
8. Streamlit dashboard
9. Kali and Wireshark validation workflow
10. Final report generation and presentation evidence

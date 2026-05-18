# Mini WIDS Dashboard

Mini WIDS is a wireless intrusion detection system for the CBS 2343 Wireless Network Security mini project. It is designed to detect and log rogue access points, deauthentication attacks, unknown devices, and weak wireless encryption from Wireshark captures or a Kali Linux monitor-mode interface.

## Required Technology Mapping

| Requirement | Project Usage |
| --- | --- |
| Python | Detection engine, packet parsing, alert rules, SQLite/CSV logging, report generation |
| Wireshark | Capture and validate wireless packets, save PCAP/PCAPNG evidence |
| Kali Linux | Lab environment for monitor mode capture and controlled wireless security testing |
| User Interface | Streamlit dashboard for alerts, AP inventory, devices, charts, and exports |

## Planned Modes

- PCAP Analysis Mode: upload or load Wireshark `.pcap` or `.pcapng` files and run detection rules.
- Live Monitor Mode: sniff packets from a Kali Linux monitor-mode wireless adapter.

## Safe Lab Boundary

Run demonstrations only on an owned lab router and owned test devices. Do not capture, disrupt, or analyze networks without permission.

## Setup

### WSL / Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
pytest
```

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -e .
pytest
```

## Quick PCAP demo

Generate a small demo pcap and run detectors from the CLI:

```bash
python scripts/generate_sample_pcap.py
python -m mini_wids.engine data/sample_pcaps/demo_capture.pcap --save
```

Or run the provided demo script (Linux/macOS):

```bash
scripts/run_pcap_demo.sh
```

## Usage

```bash
streamlit run mini_wids/ui/app.py
```

If `streamlit` is not on your PATH, use:

```bash
python -m streamlit run mini_wids/ui/app.py
```

See `docs/project-structure.md` and `docs/superpowers/plans/2026-05-15-mini-wids-dashboard.md` for the implementation map.

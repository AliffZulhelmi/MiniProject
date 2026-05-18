#!/usr/bin/env bash
# Simple demo runner: generate sample pcap, then run the engine CLI
set -euo pipefail
python scripts/generate_sample_pcap.py
python -m mini_wids.engine data/sample_pcaps/demo_capture.pcap --save

#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-wlan0mon}"
OUT="${2:-data/raw_pcaps/live_capture_$(date +%Y%m%d_%H%M%S).pcapng}"

mkdir -p "$(dirname "$OUT")"
echo "Capturing wireless traffic from $IFACE into $OUT"
sudo tshark -i "$IFACE" -I -w "$OUT"

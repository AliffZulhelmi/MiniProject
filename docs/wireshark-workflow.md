# Wireshark Workflow

## Purpose

Wireshark provides packet-level proof for every Mini WIDS alert. During the presentation, use Wireshark as the trusted evidence view and Mini WIDS as the automated detection view.

## Capture Inputs

Mini WIDS should support:

- `.pcap`
- `.pcapng`

## Useful Wireshark Display Filters

Deauthentication frames:

```text
wlan.fc.type_subtype == 0x0c
```

Disassociation frames:

```text
wlan.fc.type_subtype == 0x0a
```

Beacon frames:

```text
wlan.fc.type_subtype == 0x08
```

Probe requests:

```text
wlan.fc.type_subtype == 0x04
```

Authentication frames:

```text
wlan.fc.type_subtype == 0x0b
```

## Evidence Checklist

For each alert type:

1. Save a PCAP or PCAPNG file.
2. Apply the relevant Wireshark display filter.
3. Screenshot the matching packets.
4. Run Mini WIDS on the same capture.
5. Export the Mini WIDS alert log.

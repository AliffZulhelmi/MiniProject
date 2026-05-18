# Alert Table Normalization Design

## Purpose

Expand the Streamlit dashboard alert table so users can inspect detector results in two ways: the existing raw evidence view and a cleaner normalized view with detector-specific columns. Add a detector filter so users can focus the chart and table on one detector family.

## Scope

This change is presentation-only. It will not change detector output schemas, `process_pcap()`, alert storage, PCAP generation, or saved database payloads. Raw detector dictionaries remain the source of truth.

## Behavior

- Add a detector filter with these choices:
  - `All Detectors`
  - `Deauth`
  - `Rogue AP`
  - `Unknown Device`
  - `Weak Encryption`
- Use user-facing detector labels in dashboard tables and chart labels instead of variable-like IDs.
- Add a table mode selector:
  - `Raw`
  - `Normalized`
- Raw mode keeps one combined table with `Detector` and `Alert` columns.
- Normalized mode renders separate tables per detector type after filtering.
- Normalized table columns:
  - `Deauth`: `Attacker`, `Victim`, `Frame Count`
  - `Rogue AP`: `BSSID`, `SSID`
  - `Unknown Device`: `MAC Address`, `Info`
  - `Weak Encryption`: `BSSID`, `SSID`, `Security`
- If a detector returns an error, show it in an error-shaped row rather than crashing.
- If filters remove all rows, show an empty-state message.

## Architecture

Create `mini_wids/ui/alert_tables.py` for pure table transformation helpers. Keep `mini_wids/ui/app.py` responsible for Streamlit controls, layout, chart rendering, and save actions.

The helper module will expose:

- `DETECTOR_LABELS`
- `detector_label(detector_id)`
- `flatten_results(results)`
- `available_detector_labels(rows)`
- `filter_rows(rows, selected_label)`
- `build_raw_table(rows)`
- `build_normalized_tables(rows)`

Each flattened row will preserve:

- `detector`: raw detector ID such as `rogue_ap`
- `Detector`: display label such as `Rogue AP`
- `alert`: readable string for raw display
- `details`: original detector payload for saving and normalized formatting

## Data Flow

1. Dashboard calls `process_pcap()`.
2. `flatten_results()` converts result dictionaries into table rows.
3. User chooses detector filter and table mode.
4. `filter_rows()` narrows rows by friendly detector label.
5. Chart counts filtered rows by `Detector`.
6. Raw mode calls `build_raw_table()`.
7. Normalized mode calls `build_normalized_tables()` and displays one table per detector label.
8. Save-to-DB continues to save raw `details` payloads.

## Testing

Add focused tests for the helper module:

- Detector labels convert IDs to display labels.
- Raw table uses display labels and preserves readable alert text.
- Filtering by detector label returns only that detector.
- Normalized tables are grouped by detector label.
- Each supported detector produces the expected normalized columns.
- Error rows do not break raw or normalized table generation.

Run the full test suite after implementation.

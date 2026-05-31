"""Minimal Streamlit app to upload a PCAP or pick a sample and run detectors.

This app is intentionally small for demos: it runs `process_pcap` and shows
detector outputs. It can optionally save alerts to the repository.
"""

from pathlib import Path

import plotly.express as px
import streamlit as st

from mini_wids.engine import process_pcap
from mini_wids.reporting.report_builder import export_alerts_csv
from mini_wids.sample_pcap_generator import ALERT_TYPE_SLUGS, write_alert_type_pcap
from mini_wids.storage.repository import save_alerts
from mini_wids.ui.alert_tables import (
    available_detector_labels,
    build_normalized_tables,
    build_raw_table,
    filter_rows,
    flatten_results,
)
from mini_wids.ui.auth import require_authentication
from mini_wids.ui.sidebar import render_sidebar

ALERT_TYPE_DISPLAY = {
    "deauth": "Deauthentication Flood",
    "rogue_ap": "Rogue / Evil-Twin AP",
    "weak_encryption": "Weak Encryption",
    "unknown_device": "Unknown Device",
}

DETECTOR_DESCRIPTIONS = {
    "Deauth": "Detects deauthentication floods – excessive deauth frames from a single source attempting to disconnect clients from networks.",
    "Rogue AP": "Identifies unauthorized access points not in the whitelist. These could be evil-twin or rogue APs set up by attackers.",
    "Unknown Device": "Flags wireless devices (by MAC address) not found in the authorized devices whitelist.",
    "Weak Encryption": "Detects access points using weak or deprecated encryption methods (WEP, OPEN, TKIP) that are vulnerable to attacks.",
}

DETECTOR_DETAILS = {
    "Deauth": {
        "title": "Deauthentication Flood Detector",
        "technical_description": """
The deauthentication detector identifies denial-of-service attacks where a malicious 
actor transmits excessive IEEE 802.11 deauthentication frames from a spoofed source 
MAC address. This forces legitimate clients to disconnect from the network.

**Technical Mechanism:**
- Counts deauth frames (`is_deauth=True`) per source MAC address
- Triggers alert when a single source exceeds the threshold (default: 5 frames)
- Records both attacker MAC and victim (last observed destination MAC)
- Operates on packet-like dicts with keys: `is_deauth`, `src`, `dst`

**Detection Logic:**
The detector uses a simple counter-based approach optimized for memory efficiency:
""",
        "code_snippet": """
from collections import Counter

def detect_deauth(packets, threshold=5):
    src_counts = Counter()
    last_victim = {}
    
    for pkt in packets:
        if not pkt.get("is_deauth"):
            continue
        src = pkt.get("src")
        dst = pkt.get("dst")
        
        if src is None:
            continue
        
        src_counts[src] += 1
        if dst:
            last_victim[src] = dst
    
    alerts = []
    for src, count in src_counts.items():
        if count >= threshold:
            alerts.append({
                "attacker": src,
                "count": count,
                "victim": last_victim.get(src)
            })
    return alerts
""",
        "example_alert": """{
    "attacker": "aa:bb:cc:dd:ee:ff",
    "count": 7,
    "victim": "11:22:33:44:55:66"
}""",
        "error_handling": """
**Error Handling:**
- Non-dict packet objects are gracefully ignored with try/except
- Missing `src` field skips that packet without raising exception
- Missing `dst` field records `None` as victim but still generates alert
- Invalid MAC formats pass through – validation occurs at UI/reporting layer
        """,
    },
    "Rogue AP": {
        "title": "Rogue Access Point Detector",
        "technical_description": """
The rogue AP detector identifies unauthorized wireless access points by comparing
observed BSSIDs against a whitelist maintained in `config/authorized_aps.yml`.

**Technical Mechanism:**
- Extracts BSSID and SSID from beacon/probe response frames
- Normalizes BSSID to lowercase for case-insensitive matching
- Matches against authorized BSSID set loaded from configuration
- Flags any BSSID not found in the whitelist as rogue

**Detection Logic:**
Simple whitelist-based detection with built-in BSSID normalization:
""",
        "code_snippet": """
def detect_rogue_aps(observed, authorized_bssids=None):
    if authorized_bssids is None:
        # Load from config/authorized_aps.yml
        authorized_bssids = {b.lower() 
                            for b in load_authorized_bssids()}
    
    alerts = []
    for ap in observed:
        bssid = (ap.get("bssid") or "").lower()
        ssid = ap.get("ssid")
        
        if not bssid:
            continue
        
        if bssid not in authorized_bssids:
            alerts.append({
                "bssid": bssid,
                "ssid": ssid
            })
    
    return alerts
""",
        "example_alert": """{
    "bssid": "de:ad:be:ef:00:01",
    "ssid": "FakeNetwork"
}""",
        "error_handling": """
**Error Handling:**
- Missing BSSID field skips that AP record (empty string check)
- Empty SSID is recorded as `None` but does not prevent alerting
- Config file load errors are caught and logged separately
- Case normalization prevents BSSID matching issues
        """,
    },
    "Unknown Device": {
        "title": "Unknown Device Detector",
        "technical_description": """
The unknown device detector identifies wireless clients (by MAC address) that 
are not in the authorized device whitelist stored in `config/authorized_devices.yml`.

**Technical Mechanism:**
- Extracts MAC address from observed device packets
- Normalizes MAC to lowercase for consistent matching
- Filters out authorized MACs from configuration
- Deduplicates multiple observations of the same MAC (keeps first valid device info)

**Detection Logic:**
Whitelist-based detection with deduplication and device metadata preservation:
""",
        "code_snippet": """
def detect_unknown_devices(observed, authorized_macs=None):
    if authorized_macs is None:
        authorized_macs = {m.lower() 
                          for m in load_authorized_macs()}
    
    alerts_by_mac = {}
    for dev in observed:
        mac = (dev.get("mac") or dev.get("src") or "").lower()
        
        if not mac or mac in authorized_macs:
            continue
        
        info = dev.get("info")
        if mac not in alerts_by_mac:
            alerts_by_mac[mac] = {"mac": mac, "info": info}
        elif not alerts_by_mac[mac].get("info") and info:
            # Update with first available device info
            alerts_by_mac[mac]["info"] = info
    
    return list(alerts_by_mac.values())
""",
        "example_alert": """{
    "mac": "99:88:77:66:55:44",
    "info": "Unknown_Vendor_Device"
}""",
        "error_handling": """
**Error Handling:**
- Falls back to `src` field if `mac` field is unavailable
- Empty MAC string (after strip) is skipped silently
- Missing `info` field recorded as `None` but does not prevent alerting
- Deduplication prevents duplicate alerts for the same MAC
- Authorized MAC list load errors are caught separately
        """,
    },
    "Weak Encryption": {
        "title": "Weak Encryption Detector",
        "technical_description": """
The weak encryption detector identifies access points using deprecated or insecure
encryption protocols (WEP, OPEN, TKIP). These protocols are vulnerable to known
cryptographic attacks.

**Technical Mechanism:**
- Extracts security string from beacon/probe response frames
- Normalizes to lowercase for pattern matching
- Checks security string against insecure signal patterns
- Default insecure signals: {'wep', 'open', 'tkip'}

**Detection Logic:**
Pattern-based detection with configurable insecure signal set:
""",
        "code_snippet": """
DEFAULT_INSECURE = {"wep", "open", "tkip"}

def detect_weak_encryption(observed, 
                          insecure_signals=None):
    if insecure_signals is None:
        insecure_signals = DEFAULT_INSECURE
    
    alerts = []
    for ap in observed:
        sec = (ap.get("security") or "").lower()
        
        if not sec:
            continue
        
        for sig in insecure_signals:
            if sig in sec:
                alerts.append({
                    "bssid": ap.get("bssid"),
                    "ssid": ap.get("ssid"),
                    "security": ap.get("security")
                })
                break  # One alert per AP
    
    return alerts
""",
        "example_alert": """{
    "bssid": "11:22:33:44:55:66",
    "ssid": "LegacyNetwork",
    "security": "WEP"
}""",
        "error_handling": """
**Error Handling:**
- Empty/None security field skips that AP (continues to next)
- Security string is case-insensitive (normalized to lowercase)
- Missing BSSID/SSID recorded as `None` but does not prevent alerting
- Pattern matching uses substring search to catch variations
  (e.g., "WEP40", "TKIP+AES" would both trigger)
        """,
    },
}


@st.dialog("Generate Alert-Type PCAP")
def alert_type_modal() -> None:
    st.markdown(
        "Select the alert type you want to test. "
        "A PCAP containing frames for that threat will be generated and loaded."
    )
    chosen = st.radio(
        "Alert type",
        options=list(ALERT_TYPE_SLUGS.keys()),
        format_func=lambda key: ALERT_TYPE_DISPLAY[key],
        key="modal_alert_type_choice",
    )
    col_ok, col_cancel = st.columns(2)
    with col_ok:
        if st.button("Generate", type="primary", use_container_width=True):
            _handle_alert_type_generate(chosen)
            st.rerun()
    with col_cancel:
        if st.button("Cancel", use_container_width=True):
            st.rerun()


@st.dialog("Detector Details", width="large")
def detector_details_modal(detector_name: str) -> None:
    """Display detailed technical information about a detector."""
    try:
        if detector_name not in DETECTOR_DETAILS:
            st.error(f"Details not available for detector: {detector_name}")
            return

        details = DETECTOR_DETAILS[detector_name]
        
        st.markdown(f"## {details['title']}")
        
        st.markdown("### Overview")
        st.markdown(details['technical_description'])
        
        st.markdown("### Detection Algorithm")
        st.code(details['code_snippet'], language="python")
        
        st.markdown("### Example Alert Output")
        st.code(details['example_alert'], language="json")
        
        st.markdown("### Error Handling & Edge Cases")
        st.markdown(details['error_handling'])
        
        st.markdown("---")
        st.markdown(
            "For implementation details, see the detector source code "
            "in `mini_wids/detectors/<detector_name>.py`"
        )
    except Exception as exc:
        st.error(f"Failed to load detector details: {exc}")



def _handle_alert_type_generate(alert_type: str) -> None:
    try:
        generated = write_alert_type_pcap(alert_type)
        st.session_state.selected_pcap_path = str(generated.path)
        st.session_state.generated_pcap_seed = generated.seed
        st.session_state.generated_pcap_name = generated.path.name
        st.session_state.uploaded_pcap_name = None
    except ValueError as exc:
        st.error(f"Invalid selection: {exc}")
    except Exception as exc:
        st.error(f"Generation failed: {exc}")


st.set_page_config(page_title="Mini WIDS", layout="wide")
require_authentication()

# Custom CSS for modal width (80% of viewport) and styling
st.markdown("""
<style>
    /* Make dialog/modal wider and center it vertically + horizontally */
    [data-testid="stDialog"] {
        width: 100% !important;
        display: flex !important;
        justify-content: center !important;
        align-items: center !important;
        min-height: 100vh !important;
    }

    /* Inner dialog content sizing */
    [data-testid="stDialogInner"] {
        width: 80vw !important;
        max-width: 80vw !important;
        margin: auto !important;
    }

    /* Ensure the dialog overlay positions the dialog centrally */
    [role="dialog"] {
        position: fixed !important;
        top: 4vh !important;
        left: 50% !important;
        transform: translateX(-50%) !important;
        width: 80vw !important;
        max-width: 80vw !important;
        max-height: 92vh !important;
        overflow-y: auto !important;
        margin: 0 !important;
        z-index: 10000 !important;
    }

    [data-testid="stDialogInner"] {
        max-height: 92vh !important;
        overflow-y: auto !important;
    }

    /* Style button as link for Learn More */
    .learn-more-button {
        background-color: transparent !important;
        border: none !important;
        padding: 0 !important;
        color: #1f77e4 !important;
        text-decoration: none !important;
        font-weight: 500 !important;
        cursor: pointer !important;
        font-size: inherit !important;
    }
    .learn-more-button:hover {
        text-decoration: underline !important;
    }

    /* Vertically center contents inside Streamlit columns (helps align small buttons) */
    [data-testid="stColumns"] > div {
        display: flex !important;
        align-items: center !important;
    }

    /* Ensure inner column content also centers and fills width */
    [data-testid="stColumns"] > div > div {
        display: flex !important;
        align-items: center !important;
        width: 100% !important;
    }
</style>
""", unsafe_allow_html=True)

st.title("Mini Wireless Intrusion Detection System (WIDS)")

st.markdown(
    "Upload a PCAP (or generate the sample) to run detectors. "
    "Results are visualized below."
)

for key, default in {
    "selected_pcap_path": None,
    "uploaded_pcap_name": None,
    "generated_pcap_seed": None,
    "generated_pcap_name": None,
    "_show_alert_type_modal": False,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

render_sidebar(st.session_state)

if st.session_state.get("_show_alert_type_modal"):
    st.session_state["_show_alert_type_modal"] = False
    alert_type_modal()

uploaded = st.file_uploader("PCAP file", type=["pcap", "pcapng"])
if uploaded is not None:
    dest = Path("data/raw_pcaps")
    dest.mkdir(parents=True, exist_ok=True)
    p = dest / uploaded.name
    if st.session_state.uploaded_pcap_name != uploaded.name:
        with open(p, "wb") as fh:
            fh.write(uploaded.getbuffer())
        st.session_state.selected_pcap_path = str(p)
        st.session_state.uploaded_pcap_name = uploaded.name
        st.session_state.generated_pcap_seed = None
        st.session_state.generated_pcap_name = None

pcap_path = (
    Path(st.session_state.selected_pcap_path)
    if st.session_state.selected_pcap_path
    else None
)

if pcap_path is None:
    st.info("Upload a pcap or generate a sample pcap.")
else:
    if not pcap_path.exists():
        st.error(f"PCAP not found: {pcap_path}")
    else:
        st.write("Processing:", str(pcap_path))
        results = process_pcap(str(pcap_path))

        rows = flatten_results(results)
        detector_options = available_detector_labels(rows)
        selected_detector = st.selectbox(
            "Detector",
            detector_options,
            help="Select a detector to view its alerts."
        )
        
        # Show detector description with inline Learn More link-button
        if selected_detector in DETECTOR_DESCRIPTIONS:
            with st.container(border=True):
                col_text, col_btn = st.columns([0.88, 0.12])
                with col_text:
                    st.markdown(
                        f"**{selected_detector}:** {DETECTOR_DESCRIPTIONS[selected_detector]}"
                    )
                with col_btn:
                    if st.button("Learn More", key=f"learn_{selected_detector}", use_container_width=False):
                        detector_details_modal(selected_detector)
        
        table_mode = st.radio("Table view", ["Raw", "Normalized"], horizontal=True)
        filtered_rows = filter_rows(rows, selected_detector)

        df = build_raw_table(filtered_rows)

        if not df.empty:
            counts = df.groupby("Detector").size().reset_index(name="count")
            fig = px.bar(
                counts,
                x="Detector",
                y="count",
                color="Detector",
                title="Alerts by Detector",
            )
            st.plotly_chart(fig, width="stretch")

        st.subheader("Alerts")
        if not filtered_rows:
            st.info("No alerts match the selected detector.")
        elif table_mode == "Raw":
            st.dataframe(df.head(200))
        else:
            for detector, table in build_normalized_tables(filtered_rows).items():
                st.markdown(f"#### {detector}")
                st.dataframe(table.head(200))

        if st.button("Save alerts to DB"):
            flat = []
            for row in filtered_rows:
                details = row.get("details")
                entry = {
                    "detector": row.get("detector"),
                    **(details if isinstance(details, dict) else {"value": details}),
                }
                flat.append(entry)
            save_alerts(flat)
            st.success("Saved alerts")

        if st.button("Generate CSV report"):
            try:
                report_path = export_alerts_csv("data/exports/alerts_report.csv")
                st.success(f"Report generated: {report_path}")
            except Exception as exc:
                st.error(f"Report generation failed: {exc}")

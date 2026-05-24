"""Minimal Streamlit app to upload a PCAP or pick a sample and run detectors.

This app is intentionally small for demos: it runs `process_pcap` and shows
detector outputs. It can optionally save alerts to the repository.
"""

from pathlib import Path

import plotly.express as px
import streamlit as st

from mini_wids.engine import process_pcap
from mini_wids.sample_pcap_generator import ALERT_TYPE_SLUGS, write_alert_type_pcap
from mini_wids.storage.repository import save_alerts
from mini_wids.ui.alert_tables import (
    available_detector_labels,
    build_normalized_tables,
    build_raw_table,
    filter_rows,
    flatten_results,
)
from mini_wids.ui.sidebar import render_sidebar

ALERT_TYPE_DISPLAY = {
    "deauth": "🔴 Deauthentication Flood",
    "rogue_ap": "🟠 Rogue / Evil-Twin AP",
    "weak_encryption": "🟡 Weak Encryption",
    "unknown_device": "🔵 Unknown Device",
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


st.set_page_config(page_title="Mini WIDS Demo", layout="wide")
st.title("Mini WIDS — Demo")

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
        selected_detector = st.selectbox("Detector", detector_options)
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

"""Minimal Streamlit app to upload a PCAP or pick a sample and run detectors.

This app is intentionally small for demos: it runs `process_pcap` and shows
detector outputs. It can optionally save alerts to the repository.
"""

import streamlit as st
from pathlib import Path
from mini_wids.engine import process_pcap
from mini_wids.sample_pcap_generator import write_numbered_demo_pcap
from mini_wids.storage.repository import save_alerts
from mini_wids.ui.alert_tables import (
    available_detector_labels,
    build_normalized_tables,
    build_raw_table,
    filter_rows,
    flatten_results,
)
import plotly.express as px

st.set_page_config(page_title="Mini WIDS Demo", layout="wide")
st.title("Mini WIDS — Demo")

st.markdown(
    "Upload a PCAP (or generate the sample) to run detectors. "
    "Results are visualized below."
)

uploaded = st.file_uploader("PCAP file", type=["pcap", "pcapng"])
col1, col2 = st.columns([1, 3])

if "selected_pcap_path" not in st.session_state:
    st.session_state.selected_pcap_path = None
if "uploaded_pcap_name" not in st.session_state:
    st.session_state.uploaded_pcap_name = None
if "generated_pcap_seed" not in st.session_state:
    st.session_state.generated_pcap_seed = None

with col1:
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

    if st.button("Generate sample pcap"):
        generated = write_numbered_demo_pcap()
        st.session_state.selected_pcap_path = str(generated.path)
        st.session_state.generated_pcap_seed = generated.seed
        st.success(
            f"Generated and selected {generated.path.name} "
            f"({generated.path.stat().st_size} bytes)"
        )

    pcap_path = (
        Path(st.session_state.selected_pcap_path)
        if st.session_state.selected_pcap_path
        else None
    )
    if pcap_path is not None:
        st.caption(f"Selected PCAP: {pcap_path}")
    if st.session_state.generated_pcap_seed is not None:
        st.caption(f"Sample seed: {st.session_state.generated_pcap_seed}")

with col2:
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
                        **(
                            details if isinstance(details, dict) else {"value": details}
                        ),
                    }
                    flat.append(entry)
                save_alerts(flat)
                st.success("Saved alerts")

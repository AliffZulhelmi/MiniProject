"""Minimal Streamlit app to upload a PCAP or pick a sample and run detectors.

This app is intentionally small for demos: it runs `process_pcap` and shows
detector outputs. It can optionally save alerts to the repository.
"""

import streamlit as st
from pathlib import Path
from mini_wids.engine import process_pcap
from mini_wids.sample_pcap_generator import write_demo_pcap
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

with col1:
    if st.button("Generate sample pcap"):
        write_demo_pcap()
        st.success("Generated sample PCAP")

    pcap_path = None
    if uploaded is not None:
        dest = Path("data/raw_pcaps")
        dest.mkdir(parents=True, exist_ok=True)
        p = dest / uploaded.name
        with open(p, "wb") as fh:
            fh.write(uploaded.getbuffer())
        pcap_path = p

    if st.button("Process sample pcap"):
        pcap_path = Path("data/sample_pcaps/demo_capture.pcap")

with col2:
    if pcap_path is None:
        st.info("Upload a pcap, generate the sample, or press 'Process sample pcap'.")
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
                st.plotly_chart(fig, use_container_width=True)

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
"""Streamlit dashboard entry point."""

"""Minimal Streamlit app to upload a PCAP or pick a sample and run detectors.

This app is intentionally small for demos: it runs `process_pcap` and shows
detector outputs. It can optionally save alerts to the repository.
"""

import streamlit as st
from pathlib import Path
from mini_wids.engine import process_pcap
from mini_wids.sample_pcap_generator import write_demo_pcap
from mini_wids.storage.repository import save_alerts
import plotly.express as px
import pandas as pd

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

            # Flatten results for display and charting
            rows = []
            for det, vals in results.items():
                if isinstance(vals, dict) and vals.get("error"):
                    rows.append(
                        {
                            "detector": det,
                            "alert": "error",
                            "details": vals.get("error"),
                        }
                    )
                    continue
                try:
                    for it in vals:
                        if isinstance(it, dict):
                            rows.append(
                                {"detector": det, "alert": str(it), "details": it}
                            )
                        else:
                            rows.append(
                                {"detector": det, "alert": str(it), "details": it}
                            )
                except Exception:
                    rows.append({"detector": det, "alert": str(vals), "details": vals})

            df = pd.DataFrame(rows)

            # Chart: alerts by detector
            if not df.empty:
                counts = df.groupby("detector").size().reset_index(name="count")
                fig = px.bar(
                    counts,
                    x="detector",
                    y="count",
                    color="detector",
                    title="Alerts by Detector",
                )
                st.plotly_chart(fig, use_container_width=True)

            st.subheader("Alerts")
            st.dataframe(df[["detector", "alert"]].head(200))

            if st.button("Save alerts to DB"):
                flat = []
                for r in rows:
                    entry = {
                        "detector": r.get("detector"),
                        **(
                            r.get("details")
                            if isinstance(r.get("details"), dict)
                            else {"value": r.get("details")}
                        ),
                    }
                    flat.append(entry)
                save_alerts(flat)
                st.success("Saved alerts")
"""Streamlit dashboard entry point."""

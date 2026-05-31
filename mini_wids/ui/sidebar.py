"""Sidebar panel for PCAP sample generation."""

import streamlit as st

from mini_wids.sample_pcap_generator import write_numbered_demo_pcap
from mini_wids.ui.auth import render_logout_control


def render_sidebar(session: object) -> None:
    """Render sample generation controls inside Streamlit's native sidebar."""
    with st.sidebar:
        render_logout_control(session)
        st.divider()

        st.header("Sample Generator")
        st.caption(
            "Generate a synthetic PCAP to demo the detectors. "
            "Random mode includes all alert types while alert-type mode isolates one specific threat."
            # "Alert-type mode isolates one specific threat."
        )
        st.divider()

        st.subheader("Random PCAP")
        st.caption(
            "Generate PCAP with a randomized detector mix of deauth attacks, rogue APs, "
            "weak encryption beacons, and unknown devices."
        )
        if st.button(
            "Generate random PCAP",
            key="btn_random_sidebar",
            use_container_width=True,
        ):
            _handle_random_generate(session)

        st.divider()

        st.subheader("Alert-Type PCAP")
        st.caption("Generates a PCAP containing frames for one specific alert type.")
        if st.button(
            "Generate by alert type",
            key="btn_alert_type_sidebar",
            use_container_width=True,
        ):
            session["_show_alert_type_modal"] = True
            st.rerun()

        st.divider()

        name = session.get("generated_pcap_name")
        if name:
            st.success(f"Active: `{name}`")
            seed = session.get("generated_pcap_seed")
            if seed is not None:
                st.caption(f"Seed: `{seed}`")


def _handle_random_generate(session: object) -> None:
    try:
        generated = write_numbered_demo_pcap()
        session.selected_pcap_path = str(generated.path)
        session.generated_pcap_seed = generated.seed
        session.generated_pcap_name = generated.path.name
        session.uploaded_pcap_name = None
        st.success(
            f"Generated `{generated.path.name}` "
            f"({generated.path.stat().st_size:,} bytes)"
        )
    except Exception as exc:
        st.error(f"Generation failed: {exc}")

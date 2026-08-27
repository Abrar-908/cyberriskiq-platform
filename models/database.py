import streamlit as st
import pandas as pd
from utils.sample_data import (
    get_initial_assets_df,
    get_initial_vulnerabilities_df,
    get_initial_threats_df,
    get_initial_controls_df
)

def initialize_session_state():
    """Initializes Streamlit session state with default dataframes if not present."""
    if "assets_df" not in st.session_state:
        st.session_state.assets_df = get_initial_assets_df()

    if "vulns_df" not in st.session_state:
        st.session_state.vulns_df = get_initial_vulnerabilities_df()

    if "threats_df" not in st.session_state:
        st.session_state.threats_df = get_initial_threats_df()

    if "controls_df" not in st.session_state:
        st.session_state.controls_df = get_initial_controls_df()

    if "budget_limit" not in st.session_state:
        st.session_state.budget_limit = 350000

    if "mc_simulations" not in st.session_state:
        st.session_state.mc_simulations = 10000

def reset_to_defaults():
    """Resets all dataframes in session state to baseline sample datasets."""
    st.session_state.assets_df = get_initial_assets_df()
    st.session_state.vulns_df = get_initial_vulnerabilities_df()
    st.session_state.threats_df = get_initial_threats_df()
    st.session_state.controls_df = get_initial_controls_df()

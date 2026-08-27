import sqlite3
import pandas as pd
import streamlit as st
import os
from utils.sample_data import (
    get_initial_assets_df,
    get_initial_vulnerabilities_df,
    get_initial_threats_df,
    get_initial_controls_df,
    get_initial_incidents_df
)

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "cyberrisk_ai.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_sqlite_db(force_reset: bool = False):
    """Initializes the SQLite database tables and seeds them if empty or forced."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create tables if not exist
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        asset_id TEXT PRIMARY KEY,
        asset_name TEXT,
        asset_type TEXT,
        asset_value REAL,
        criticality INTEGER,
        business_importance TEXT,
        internet_exposure TEXT,
        data_sensitivity TEXT,
        number_of_users INTEGER,
        location TEXT,
        system_availability TEXT,
        owner TEXT,
        status TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        vulnerability_id TEXT PRIMARY KEY,
        cve_id TEXT,
        vulnerability_name TEXT,
        cvss_score REAL,
        severity TEXT,
        exploitability REAL,
        vulnerability_age_days INTEGER,
        patch_status TEXT,
        public_exploit TEXT,
        kev_status TEXT,
        affected_asset TEXT,
        attack_vector TEXT,
        attack_complexity TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        threat_id TEXT PRIMARY KEY,
        threat_name TEXT,
        threat_type TEXT,
        severity TEXT,
        frequency REAL,
        likelihood REAL,
        attack_vector TEXT,
        threat_actor TEXT,
        affected_asset TEXT,
        historical_attack_count INTEGER,
        exploit_availability TEXT,
        threat_intel_score REAL,
        status TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_controls (
        control_id TEXT PRIMARY KEY,
        control_name TEXT,
        category TEXT,
        implementation_cost REAL,
        maintenance_cost REAL,
        effectiveness REAL,
        coverage REAL,
        risk_reduction_value REAL,
        detection_capability REAL,
        prevention_capability REAL,
        status TEXT,
        target_threat TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        date TEXT,
        incident_type TEXT,
        affected_asset TEXT,
        financial_loss REAL,
        downtime_hours REAL,
        root_cause TEXT,
        severity TEXT,
        resolution_status TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        alert_type TEXT,
        severity TEXT,
        title TEXT,
        message TEXT,
        related_asset TEXT,
        risk_score REAL,
        created_at TEXT,
        status TEXT
    );
    """)

    conn.commit()

    # Check if empty, seed default data
    cursor.execute("SELECT COUNT(*) FROM assets")
    count = cursor.fetchone()[0]

    if count == 0 or force_reset:
        cursor.execute("DELETE FROM assets")
        cursor.execute("DELETE FROM vulnerabilities")
        cursor.execute("DELETE FROM threats")
        cursor.execute("DELETE FROM security_controls")
        cursor.execute("DELETE FROM incidents")
        cursor.execute("DELETE FROM alerts")
        conn.commit()

        # Seed dataframes
        get_initial_assets_df().to_sql("assets", conn, if_exists="append", index=False)
        get_initial_vulnerabilities_df().to_sql("vulnerabilities", conn, if_exists="append", index=False)
        get_initial_threats_df().to_sql("threats", conn, if_exists="append", index=False)
        get_initial_controls_df().to_sql("security_controls", conn, if_exists="append", index=False)
        get_initial_incidents_df().to_sql("incidents", conn, if_exists="append", index=False)

    conn.close()

def load_data_from_db():
    """Loads all tables from SQLite into Pandas DataFrames."""
    conn = get_db_connection()
    assets_df = pd.read_sql_query("SELECT * FROM assets", conn)
    vulns_df = pd.read_sql_query("SELECT * FROM vulnerabilities", conn)
    threats_df = pd.read_sql_query("SELECT * FROM threats", conn)
    controls_df = pd.read_sql_query("SELECT * FROM security_controls", conn)
    incidents_df = pd.read_sql_query("SELECT * FROM incidents", conn)
    alerts_df = pd.read_sql_query("SELECT * FROM alerts", conn)
    conn.close()
    return assets_df, vulns_df, threats_df, controls_df, incidents_df, alerts_df

def save_dataframe_to_db(table_name: str, df: pd.DataFrame):
    """Saves an updated DataFrame back to the SQLite table."""
    conn = get_db_connection()
    df.to_sql(table_name, conn, if_exists="replace", index=False)
    conn.close()

def initialize_session_state():
    """Initializes Streamlit session state and synchronizes with SQLite."""
    init_sqlite_db()

    assets, vulns, threats, controls, incidents, alerts = load_data_from_db()

    if "assets_df" not in st.session_state:
        st.session_state.assets_df = assets

    if "vulns_df" not in st.session_state:
        st.session_state.vulns_df = vulns

    if "threats_df" not in st.session_state:
        st.session_state.threats_df = threats

    if "controls_df" not in st.session_state:
        st.session_state.controls_df = controls

    if "incidents_df" not in st.session_state:
        st.session_state.incidents_df = incidents

    if "alerts_df" not in st.session_state:
        st.session_state.alerts_df = alerts

    if "budget_limit" not in st.session_state:
        st.session_state.budget_limit = 2500000  # ₹25 Lakhs default

    if "mc_simulations" not in st.session_state:
        st.session_state.mc_simulations = 10000

    if "user_role" not in st.session_state:
        st.session_state.user_role = "Executive"

def reset_to_defaults():
    """Forces a complete database reset to baseline data."""
    init_sqlite_db(force_reset=True)
    assets, vulns, threats, controls, incidents, alerts = load_data_from_db()
    st.session_state.assets_df = assets
    st.session_state.vulns_df = vulns
    st.session_state.threats_df = threats
    st.session_state.controls_df = controls
    st.session_state.incidents_df = incidents
    st.session_state.alerts_df = alerts

import pytest
import pandas as pd
from models.fair_engine import calculate_deterministic_fair, run_monte_carlo_simulation
from utils.sample_data import get_initial_assets_df, get_initial_vulnerabilities_df, get_initial_threats_df, get_initial_controls_df

def test_fair_calculation():
    assets = get_initial_assets_df()
    vulns = get_initial_vulnerabilities_df()
    threats = get_initial_threats_df()
    controls = get_initial_controls_df()

    metrics = calculate_deterministic_fair(assets, vulns, threats, controls)

    assert metrics["total_asset_value"] > 0
    assert metrics["inherent_ale"] > metrics["residual_ale"]
    assert 0.0 <= metrics["enterprise_risk_index"] <= 100.0
    assert len(metrics["asset_risk_df"]) == len(assets)

def test_monte_carlo_simulation():
    assets = get_initial_assets_df()
    vulns = get_initial_vulnerabilities_df()
    threats = get_initial_threats_df()
    controls = get_initial_controls_df()

    sim = run_monte_carlo_simulation(assets, vulns, threats, controls, num_simulations=500)

    assert sim["p10"] < sim["p50"] < sim["p90"] < sim["p99"]
    assert sim["var_95"] > sim["p50"]
    assert len(sim["lec_df"]) > 0

import sys
from models.fair_engine import calculate_deterministic_fair, run_monte_carlo_simulation
from models.ml_engine import CyberRiskMLEngine
from models.optimizer_engine import optimize_security_investments
from utils.sample_data import (
    get_initial_assets_df,
    get_initial_vulnerabilities_df,
    get_initial_threats_df,
    get_initial_controls_df
)

def test_pipeline():
    print("Testing sample data loading...")
    assets = get_initial_assets_df()
    vulns = get_initial_vulnerabilities_df()
    threats = get_initial_threats_df()
    controls = get_initial_controls_df()
    assert len(assets) > 0
    assert len(vulns) > 0
    assert len(threats) > 0
    assert len(controls) > 0
    print("Sample data loaded successfully.")

    print("Testing FAIR & Monte Carlo engine...")
    sim = run_monte_carlo_simulation(assets, vulns, threats, controls, num_simulations=500)
    assert sim["p50"] > 0
    assert sim["var_95"] > sim["p50"]
    print("FAIR & Monte Carlo executed successfully.")

    print("Testing Optimizer engine...")
    opt = optimize_security_investments(controls, budget_limit=300000, current_ale=2000000)
    assert opt["status"] == "Optimal"
    assert len(opt["selected_controls_df"]) > 0
    print("Optimizer executed successfully.")

    print("Testing ML Risk engine...")
    ml = CyberRiskMLEngine(model_type="XGBoost")
    assert ml.metrics["R2"] is not None
    pred = ml.predict({
        "Asset_Value": 1000000,
        "Asset_Criticality": 5,
        "Internet_Exposed": 1,
        "Num_Users": 10000,
        "Data_Sensitivity": 4,
        "CVSS_Score": 9.8,
        "Exploitability": 0.95,
        "Vuln_Age_Days": 100,
        "Weaponized_Exploit": 1,
        "Patch_Status_Score": 0.0,
        "Threat_Frequency": 10.0,
        "Threat_Intel_Score": 90.0,
        "Threat_Severity": 4,
        "Control_Effectiveness": 80.0,
        "Control_Coverage": 85.0,
        "Prevention_Capability": 80.0,
        "Detection_Capability": 80.0
    })
    assert pred > 0
    print(f"ML Prediction for test asset: ${pred:,.2f}")
    print("ALL TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_pipeline()

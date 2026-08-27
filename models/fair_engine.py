import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple

def calculate_deterministic_fair(
    assets_df: pd.DataFrame,
    vulns_df: pd.DataFrame,
    threats_df: pd.DataFrame,
    controls_df: pd.DataFrame
) -> Dict[str, Any]:
    """
    Computes deterministic FAIR metrics and per-asset explainability in Indian Rupees (INR).
    """
    total_asset_value = float(assets_df["asset_value"].sum())
    
    # Active security control attenuation factor
    active_controls = controls_df[controls_df["status"] == "Active"]
    if len(active_controls) > 0:
        avg_control_eff = (active_controls["effectiveness"] / 100.0 * 
                           active_controls["coverage"] / 100.0).mean()
    else:
        avg_control_eff = 0.15

    control_mitigation_factor = max(0.05, 1.0 - avg_control_eff)
    
    # Aggregate Vulnerability Exploitability factor
    unpatched_vulns = vulns_df[vulns_df["patch_status"] != "Patched"]
    if len(unpatched_vulns) > 0:
        avg_exploitability = float(unpatched_vulns["exploitability"].mean())
    else:
        avg_exploitability = 0.20
        
    # Threat Event Frequency (annual sum)
    annual_threat_events = float(threats_df["frequency"].sum())
    
    # Enterprise Inherent Risk (Loss Event Frequency * Loss Magnitude without controls)
    loss_event_frequency_inherent = annual_threat_events * avg_exploitability
    avg_loss_magnitude_inherent = total_asset_value * 0.12  # Avg breach impact ~12% of portfolio
    inherent_ale = loss_event_frequency_inherent * avg_loss_magnitude_inherent
    
    # Enterprise Residual Risk (with current active security controls)
    loss_event_frequency_residual = loss_event_frequency_inherent * control_mitigation_factor
    residual_ale = loss_event_frequency_residual * (avg_loss_magnitude_inherent * 0.70)
    
    risk_reduction_achieved = inherent_ale - residual_ale
    enterprise_risk_index = min(100.0, (residual_ale / (total_asset_value * 0.08)) * 100.0)

    # Per-Asset Risk Breakdown & Explainability
    asset_risk_records = []
    for _, asset in assets_df.iterrows():
        a_id = asset["asset_id"]
        a_val = float(asset["asset_value"])
        a_crit = int(asset["criticality"])
        is_internet = 1.4 if "Yes" in str(asset["internet_exposure"]) else 0.8
        
        # Associated unpatched CVEs
        asset_cves = vulns_df[(vulns_df["affected_asset"] == a_id) & (vulns_df["patch_status"] != "Patched")]
        cve_count = len(asset_cves)
        cve_max_cvss = asset_cves["cvss_score"].max() if cve_count > 0 else 3.0
        
        # Threat frequency targeted at this asset
        asset_threats = threats_df[threats_df["affected_asset"] == a_id]
        asset_tf = asset_threats["frequency"].sum() if len(asset_threats) > 0 else (annual_threat_events / len(assets_df))
        
        asset_lef = asset_tf * (cve_max_cvss / 10.0) * is_internet * control_mitigation_factor
        exposure_factor = (0.05 + 0.04 * a_crit)
        asset_sle = a_val * exposure_factor
        asset_ale = asset_lef * asset_sle
        
        # Normalized Risk Score (0-100)
        risk_score = min(100.0, ((cve_max_cvss / 10.0) * 35.0 + (a_crit / 5.0) * 25.0 + (is_internet / 1.4) * 20.0 + (control_mitigation_factor) * 20.0))

        # Explainability Factor Weights (%)
        exp_cvss = round((cve_max_cvss / 10.0) * 35.0, 1)
        exp_crit = round((a_crit / 5.0) * 25.0, 1)
        exp_exp = round((is_internet / 1.4) * 20.0, 1)
        exp_gap = round((control_mitigation_factor) * 20.0, 1)

        asset_risk_records.append({
            "Asset ID": a_id,
            "Asset Name": asset["asset_name"],
            "Asset Value (INR)": a_val,
            "Criticality": a_crit,
            "Active CVEs": cve_count,
            "Max CVSS": cve_max_cvss,
            "Risk Score": round(risk_score, 1),
            "SLE (INR)": round(asset_sle, 2),
            "Annual Event Freq": round(asset_lef, 3),
            "Asset ALE (INR)": round(asset_ale, 2),
            "Risk Level": "Critical" if risk_score >= 76 else "High" if risk_score >= 51 else "Medium" if risk_score >= 26 else "Low",
            "Factor_CVSS": exp_cvss,
            "Factor_Criticality": exp_crit,
            "Factor_Exposure": exp_exp,
            "Factor_ControlGap": exp_gap,
            "Explanation": f"High risk driven by {cve_count} active CVEs (Max CVSS {cve_max_cvss}), internet exposure={asset['internet_exposure']}, and business criticality {a_crit}/5."
        })
        
    asset_risk_df = pd.DataFrame(asset_risk_records).sort_values(by="Risk Score", ascending=False)

    return {
        "total_asset_value": total_asset_value,
        "inherent_ale": inherent_ale,
        "residual_ale": residual_ale,
        "risk_reduction_achieved": risk_reduction_achieved,
        "enterprise_risk_index": round(enterprise_risk_index, 1),
        "control_mitigation_factor": control_mitigation_factor,
        "asset_risk_df": asset_risk_df
    }

def run_monte_carlo_simulation(
    assets_df: pd.DataFrame,
    vulns_df: pd.DataFrame,
    threats_df: pd.DataFrame,
    controls_df: pd.DataFrame,
    num_simulations: int = 10000
) -> Dict[str, Any]:
    """
    Executes a probabilistic Monte Carlo simulation using LogNormal distributions
    to quantify annual cyber loss exceedance in Indian Rupees (INR).
    """
    np.random.seed(42)
    fair_metrics = calculate_deterministic_fair(assets_df, vulns_df, threats_df, controls_df)
    
    mean_ale = fair_metrics["residual_ale"]
    inherent_ale = fair_metrics["inherent_ale"]
    
    sigma_inherent = 0.85
    mu_inherent = np.log(max(10000.0, inherent_ale)) - 0.5 * (sigma_inherent ** 2)
    simulated_inherent_losses = np.random.lognormal(mean=mu_inherent, sigma=sigma_inherent, size=num_simulations)
    
    sigma_residual = 0.70
    mu_residual = np.log(max(10000.0, mean_ale)) - 0.5 * (sigma_residual ** 2)
    simulated_residual_losses = np.random.lognormal(mean=mu_residual, sigma=sigma_residual, size=num_simulations)
    
    sorted_inherent = np.sort(simulated_inherent_losses)[::-1]
    sorted_residual = np.sort(simulated_residual_losses)[::-1]
    exceedance_probs = (np.arange(1, num_simulations + 1) / num_simulations) * 100.0
    
    p10 = float(np.percentile(simulated_residual_losses, 10))
    p50 = float(np.percentile(simulated_residual_losses, 50))
    p90 = float(np.percentile(simulated_residual_losses, 90))
    p99 = float(np.percentile(simulated_residual_losses, 99))
    var_95 = float(np.percentile(simulated_residual_losses, 95))
    expected_shortfall_95 = float(simulated_residual_losses[simulated_residual_losses >= var_95].mean())
    
    lec_df = pd.DataFrame({
        "Exceedance_Probability (%)": exceedance_probs[::50],
        "Residual_Loss (INR)": sorted_residual[::50],
        "Inherent_Loss (INR)": sorted_inherent[::50]
    })
    
    return {
        "p10": p10,
        "p50": p50,
        "p90": p90,
        "p99": p99,
        "var_95": var_95,
        "expected_shortfall_95": expected_shortfall_95,
        "simulated_residual_losses": simulated_residual_losses,
        "lec_df": lec_df,
        "deterministic": fair_metrics
    }

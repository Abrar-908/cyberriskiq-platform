import pandas as pd
from datetime import datetime
from typing import List, Dict, Any

def generate_continuous_alerts(
    assets_df: pd.DataFrame,
    vulns_df: pd.DataFrame,
    threats_df: pd.DataFrame,
    controls_df: pd.DataFrame,
    fair_metrics: Dict[str, Any]
) -> pd.DataFrame:
    """
    Evaluates real-time telemetry across the enterprise to generate actionable
    CRITICAL, HIGH, WARNING, and INFO alerts.
    """
    alerts = []
    alert_counter = 1

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")

    # 1. Check for Unpatched Known Exploited Vulnerabilities (KEVs) on Internet-Exposed Assets
    unpatched_kevs = vulns_df[(vulns_df["patch_status"] == "Unpatched") & (vulns_df["kev_status"].str.contains("Known Exploited", na=False))]
    for _, v in unpatched_kevs.iterrows():
        a_id = v["affected_asset"]
        asset_row = assets_df[assets_df["asset_id"] == a_id]
        is_internet = "Yes" in str(asset_row["internet_exposure"].values[0]) if len(asset_row) > 0 else False
        
        severity = "CRITICAL" if is_internet else "HIGH"
        alerts.append({
            "alert_id": f"ALT-{alert_counter:03d}",
            "alert_type": "Unpatched Weaponized CVE",
            "severity": severity,
            "title": f"CISA KEV Alert: {v['cve_id']} on {a_id}",
            "message": f"Critical vulnerability {v['vulnerability_name']} (CVSS {v['cvss_score']}) is active in the wild with weaponized exploit.",
            "related_asset": a_id,
            "risk_score": float(v["cvss_score"]) * 10.0,
            "created_at": now_str,
            "status": "Active"
        })
        alert_counter += 1

    # 2. Check for High-Risk Assets exceeding ALE Threshold (> ₹50 Lakhs)
    asset_risk_df = fair_metrics.get("asset_risk_df", pd.DataFrame())
    if not asset_risk_df.empty:
        high_risk_assets = asset_risk_df[asset_risk_df["Asset ALE (INR)"] > 5000000]
        for _, a in high_risk_assets.iterrows():
            alerts.append({
                "alert_id": f"ALT-{alert_counter:03d}",
                "alert_type": "High Risk Asset",
                "severity": "CRITICAL" if a["Asset ALE (INR)"] > 15000000 else "HIGH",
                "title": f"High Financial Risk: {a['Asset ID']} ({a['Asset Name']})",
                "message": f"Annualized Loss Expectancy exceeds threshold at ₹{a['Asset ALE (INR)']/100000:.2f} Lakhs with {a['Active CVEs']} active CVEs.",
                "related_asset": a["Asset ID"],
                "risk_score": float(a["Risk Score"]),
                "created_at": now_str,
                "status": "Active"
            })
            alert_counter += 1

    # 3. Check for Security Control Coverage Gaps (< 85% coverage on critical assets)
    active_controls = controls_df[controls_df["status"] == "Active"]
    low_cov_controls = active_controls[active_controls["coverage"] < 85]
    for _, c in low_cov_controls.iterrows():
        alerts.append({
            "alert_id": f"ALT-{alert_counter:03d}",
            "alert_type": "Control Coverage Gap",
            "severity": "WARNING",
            "title": f"Suboptimal Coverage: {c['control_name']}",
            "message": f"Control coverage is currently at {c['coverage']}%. Expanding coverage to 95%+ will mitigate ₹{c['risk_reduction_value']/100000:.1f} Lakhs in exposure.",
            "related_asset": "Enterprise-Wide",
            "risk_score": 55.0,
            "created_at": now_str,
            "status": "Active"
        })
        alert_counter += 1

    # 4. Check for High Threat Intelligence Scores (> 90)
    top_threats = threats_df[threats_df["threat_intel_score"] >= 92]
    for _, t in top_threats.iterrows():
        alerts.append({
            "alert_id": f"ALT-{alert_counter:03d}",
            "alert_type": "Adversary Campaign",
            "severity": "HIGH",
            "title": f"Elevated Threat Activity: {t['threat_name']}",
            "message": f"Threat intel score reached {t['threat_intel_score']}/100. Threat actor: {t['threat_actor']}.",
            "related_asset": t["affected_asset"],
            "risk_score": float(t["threat_intel_score"]),
            "created_at": now_str,
            "status": "Active"
        })
        alert_counter += 1

    return pd.DataFrame(alerts)

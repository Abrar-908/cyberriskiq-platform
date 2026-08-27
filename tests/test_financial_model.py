import pytest
from utils.currency import format_inr, format_inr_full
from models.ml_engine import CyberRiskMLEngine

def test_inr_formatting():
    assert format_inr(45000000) == "₹4.50 Cr"
    assert format_inr(2500000) == "₹25.00 L"
    assert format_inr(50000) == "₹50,000"

def test_ml_risk_engine():
    ml = CyberRiskMLEngine()
    assert ml.metrics["R2"] is not None

    loss, prob = ml.predict({
        "Asset_Value": 25000000,
        "Asset_Criticality": 5,
        "Internet_Exposed": 1,
        "Num_Users": 100000,
        "Data_Sensitivity": 4,
        "CVSS_Score": 9.8,
        "Exploitability": 0.95,
        "Vuln_Age_Days": 100,
        "Weaponized_Exploit": 1,
        "Patch_Status_Score": 0.0,
        "Threat_Frequency": 15.0,
        "Threat_Intel_Score": 90.0,
        "Threat_Severity": 4,
        "Control_Effectiveness": 80.0,
        "Control_Coverage": 85.0,
        "Prevention_Capability": 80.0,
        "Detection_Capability": 80.0
    })

    assert loss > 0
    assert 0.0 <= prob <= 1.0

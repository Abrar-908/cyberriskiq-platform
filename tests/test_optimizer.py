import pytest
from models.optimizer_engine import optimize_security_investments
from utils.sample_data import get_initial_controls_df

def test_pulp_optimizer_budget_constraint():
    controls = get_initial_controls_df()
    budget = 2500000.0  # ₹25 Lakhs

    result = optimize_security_investments(controls, budget_limit=budget, current_ale=45000000.0)

    assert result["status"] == "Optimal"
    assert result["total_spend"] <= budget
    assert result["total_risk_reduced"] > 0
    assert len(result["selected_controls_df"]) > 0
    assert len(result["frontier_df"]) == 15

import pulp
import pandas as pd
import numpy as np
from typing import Dict, Any, List

def optimize_security_investments(
    controls_df: pd.DataFrame,
    budget_limit: float,
    current_ale: float = 35000000.0
) -> Dict[str, Any]:
    """
    Mixed-Integer Linear Programming (MILP) Security Portfolio Optimization using PuLP in INR.
    Maximizes expected risk reduction while strictly constraining total cost <= budget_limit.
    """
    prob = pulp.LpProblem("Cyber_Security_Investment_Optimization", pulp.LpMaximize)
    
    n_controls = len(controls_df)
    control_vars = [pulp.LpVariable(f"x_{i}", cat=pulp.LpBinary) for i in range(n_controls)]
    
    costs = []
    benefits = []
    
    for i, (_, row) in enumerate(controls_df.iterrows()):
        total_cost = float(row["implementation_cost"]) + float(row["maintenance_cost"])
        eff = float(row["effectiveness"]) / 100.0
        cov = float(row["coverage"]) / 100.0
        raw_reduction = float(row["risk_reduction_value"])
        
        weighted_benefit = raw_reduction * eff * cov
        costs.append(total_cost)
        benefits.append(weighted_benefit)
        
    # Objective: Maximize total weighted risk reduction
    prob += pulp.lpSum([benefits[i] * control_vars[i] for i in range(n_controls)])
    
    # Constraint: Total cost <= budget_limit
    prob += pulp.lpSum([costs[i] * control_vars[i] for i in range(n_controls)]) <= budget_limit
    
    # Solve using default PuLP solver silently
    prob.solve(pulp.PULP_CBC_CMD(msg=False))
    
    selected_indices = [i for i in range(n_controls) if pulp.value(control_vars[i]) == 1.0]
    
    selected_controls_df = controls_df.iloc[selected_indices].copy()
    
    total_spend = sum([costs[i] for i in selected_indices])
    total_risk_reduced = sum([benefits[i] for i in selected_indices])
    unselected_controls_df = controls_df.drop(index=controls_df.index[selected_indices]).copy()
    
    residual_ale_after_optimization = max(10000.0, current_ale - total_risk_reduced)
    roi_percentage = ((total_risk_reduced - total_spend) / total_spend * 100.0) if total_spend > 0 else 0.0
    risk_reduction_pct = (total_risk_reduced / current_ale * 100.0) if current_ale > 0 else 0.0
    
    # Generate Investment Efficient Frontier Curve (budget increments in INR)
    max_portfolio_cost = sum(costs)
    budget_steps = np.linspace(200000, max_portfolio_cost * 1.05, 15)
    frontier_data = []
    
    for b in budget_steps:
        sub_prob = pulp.LpProblem("Frontier", pulp.LpMaximize)
        sub_vars = [pulp.LpVariable(f"s_{j}", cat=pulp.LpBinary) for j in range(n_controls)]
        sub_prob += pulp.lpSum([benefits[j] * sub_vars[j] for j in range(n_controls)])
        sub_prob += pulp.lpSum([costs[j] * sub_vars[j] for j in range(n_controls)]) <= b
        sub_prob.solve(pulp.PULP_CBC_CMD(msg=False))
        
        b_selected = [j for j in range(n_controls) if pulp.value(sub_vars[j]) == 1.0]
        b_spend = sum([costs[j] for j in b_selected])
        b_reduced = sum([benefits[j] for j in b_selected])
        
        frontier_data.append({
            "Budget (INR)": round(b, 2),
            "Actual Spend (INR)": round(b_spend, 2),
            "Max Risk Reduction (INR)": round(b_reduced, 2),
            "Residual ALE (INR)": round(max(10000.0, current_ale - b_reduced), 2),
            "Controls Count": len(b_selected)
        })
        
    frontier_df = pd.DataFrame(frontier_data)
    
    return {
        "status": pulp.LpStatus[prob.status],
        "selected_controls_df": selected_controls_df,
        "unselected_controls_df": unselected_controls_df,
        "total_spend": total_spend,
        "total_risk_reduced": total_risk_reduced,
        "risk_reduction_pct": round(risk_reduction_pct, 1),
        "residual_ale_after_optimization": residual_ale_after_optimization,
        "roi_percentage": round(roi_percentage, 1),
        "frontier_df": frontier_df
    }

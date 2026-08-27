import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# Page Configuration
st.set_page_config(
    page_title="CyberRisk AI — Continuous Cyber Risk Quantification & Investment Optimization",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Import internal modules
from utils.ui_components import CUSTOM_CSS, render_kpi_card
from utils.currency import format_inr, format_inr_full
from models.database import initialize_session_state, reset_to_defaults, save_dataframe_to_db
from models.fair_engine import calculate_deterministic_fair, run_monte_carlo_simulation
from models.ml_engine import CyberRiskMLEngine
from models.optimizer_engine import optimize_security_investments
from models.alert_engine import generate_continuous_alerts
from services.threat_intel import query_nvd_cve, get_mitre_attack_matrix

# Inject Custom CSS
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Initialize Database and Session State
initialize_session_state()

# Cache ML Model
@st.cache_resource
def load_ml_engine():
    return CyberRiskMLEngine(model_type="Random Forest")

ml_engine = load_ml_engine()

# Run Live FAIR and Monte Carlo Engine
sim_results = run_monte_carlo_simulation(
    st.session_state.assets_df,
    st.session_state.vulns_df,
    st.session_state.threats_df,
    st.session_state.controls_df,
    num_simulations=st.session_state.mc_simulations
)
fair_metrics = sim_results["deterministic"]

# Generate Continuous Alerts
live_alerts_df = generate_continuous_alerts(
    st.session_state.assets_df,
    st.session_state.vulns_df,
    st.session_state.threats_df,
    st.session_state.controls_df,
    fair_metrics
)

# Sidebar Navigation & Role Management
with st.sidebar:
    st.markdown('<div class="cyber-header" style="font-size: 1.5rem;">🛡️ CyberRisk AI</div>', unsafe_allow_html=True)
    st.caption("AI-Powered Cyber Risk Quantification & Investment Optimization")
    st.divider()
    
    st.subheader("👤 Role-Based View")
    user_role = st.selectbox(
        "Current Persona",
        options=["Executive", "Security Analyst", "Admin"],
        index=0 if st.session_state.user_role == "Executive" else (1 if st.session_state.user_role == "Security Analyst" else 2)
    )
    st.session_state.user_role = user_role

    st.divider()
    st.subheader("⚙️ Investment & Simulation")
    budget_input = st.slider(
        "Cybersecurity Budget (INR)",
        min_value=200000,
        max_value=15000000,
        value=int(st.session_state.budget_limit),
        step=100000,
        format="₹%d"
    )
    st.session_state.budget_limit = budget_input
    st.caption(f"Allocated: **{format_inr(budget_input)}**")

    mc_runs = st.select_slider(
        "Monte Carlo Runs",
        options=[1000, 5000, 10000, 20000],
        value=st.session_state.mc_simulations
    )
    st.session_state.mc_simulations = mc_runs

    st.divider()
    if st.button("🔄 Reset SQLite Database", use_container_width=True):
        reset_to_defaults()
        st.success("Database restored to baseline seed data!")
        st.rerun()

    st.divider()
    critical_alert_count = len(live_alerts_df[live_alerts_df["severity"] == "CRITICAL"])
    st.markdown(f"🚨 **Active Alerts:** `{len(live_alerts_df)}` (`{critical_alert_count} Critical`)")
    st.caption("Framework Alignments:\n• FAIR Model & Monte Carlo\n• NIST CSF & CISA KEV\n• MITRE ATT&CK Enterprise\n• PuLP MILP 0-1 Knapsack")

# Main Header
st.markdown('<div class="cyber-header">AI-Powered Continuous Cyber Risk Quantification & Investment Optimization</div>', unsafe_allow_html=True)
st.markdown('<div class="cyber-subtitle">Real-time financial risk exposure modeling, probabilistic loss forecasting (INR ₹), and mathematical investment optimization</div>', unsafe_allow_html=True)

# Top Navigation Tabs
tab_exec, tab_analysis, tab_opt, tab_ml, tab_alerts, tab_incidents, tab_assets, tab_mitre, tab_reports = st.tabs([
    "📊 Executive Dashboard",
    "🔍 Risk Analysis & Explainability",
    "💼 Investment Optimizer",
    "🧠 AI/ML Risk Engine",
    f"🚨 Alert Center ({len(live_alerts_df)})",
    "📝 Incident History",
    "🏛️ Asset & Security Telemetry",
    "🌐 MITRE ATT&CK & Intel",
    "📄 Executive Report & Export"
])

# ==========================================
# TAB 1: EXECUTIVE DASHBOARD
# ==========================================
with tab_exec:
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(render_kpi_card("Total Portfolio Value", format_inr(fair_metrics['total_asset_value']), color_class="val-cyan", subtext="20 Monitored Enterprise Assets"), unsafe_allow_html=True)
    with c2:
        st.markdown(render_kpi_card("Inherent Loss (ALE)", format_inr(fair_metrics['inherent_ale']), delta="Unmitigated", color_class="val-red", subtext="Without active controls"), unsafe_allow_html=True)
    with c3:
        st.markdown(render_kpi_card("Residual Loss (ALE)", format_inr(fair_metrics['residual_ale']), delta=f"-{format_inr(fair_metrics['risk_reduction_achieved'])}", color_class="val-amber", subtext="With current controls"), unsafe_allow_html=True)
    with c4:
        st.markdown(render_kpi_card("VaR (95% Confidence)", format_inr(sim_results['var_95']), color_class="val-purple", subtext="Annual worst-case loss"), unsafe_allow_html=True)
    with c5:
        risk_color = "val-green" if fair_metrics['enterprise_risk_index'] < 30 else ("val-amber" if fair_metrics['enterprise_risk_index'] < 60 else "val-red")
        st.markdown(render_kpi_card("Enterprise Risk Score", f"{fair_metrics['enterprise_risk_index']} / 100", color_class=risk_color, subtext="Normalized FAIR Index"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Loss Exceedance Curve & Risk Heatmap
    col_lec, col_heatmap = st.columns([6, 5])
    
    with col_lec:
        st.subheader("📈 Loss Exceedance Curve (Monte Carlo Simulation)")
        lec_df = sim_results["lec_df"]
        fig_lec = go.Figure()
        fig_lec.add_trace(go.Scatter(
            x=lec_df["Exceedance_Probability (%)"],
            y=lec_df["Inherent_Loss (INR)"] / 100000.0,
            mode='lines',
            name='Inherent Risk (Unmitigated)',
            line=dict(color='#ef4444', width=2.5, dash='dot')
        ))
        fig_lec.add_trace(go.Scatter(
            x=lec_df["Exceedance_Probability (%)"],
            y=lec_df["Residual_Loss (INR)"] / 100000.0,
            mode='lines',
            name='Residual Risk (Current Controls)',
            line=dict(color='#38bdf8', width=3)
        ))
        fig_lec.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(15,23,42,0.6)',
            font=dict(color='#94a3b8'),
            xaxis=dict(title='Probability of Exceeding Loss (%)', gridcolor='rgba(255,255,255,0.08)'),
            yaxis=dict(title='Annual Financial Loss (₹ Lakhs)', gridcolor='rgba(255,255,255,0.08)'),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=20, r=20, t=30, b=20),
            height=340
        )
        st.plotly_chart(fig_lec, use_container_width=True)

    with col_heatmap:
        st.subheader("🗺️ 5x5 Threat-Asset Risk Matrix")
        heatmap_z = np.array([
            [15, 32, 58, 85, 98],
            [10, 22, 45, 72, 88],
            [6,  15, 34, 55, 75],
            [3,  8,  18, 35, 52],
            [1,  4,  10, 18, 30]
        ])
        fig_heat = px.imshow(
            heatmap_z,
            labels=dict(x="Asset Business Impact", y="Threat Likelihood / Frequency", color="Risk Score"),
            x=['Negligible (1)', 'Minor (2)', 'Moderate (3)', 'Major (4)', 'Catastrophic (5)'],
            y=['Frequent (5)', 'Likely (4)', 'Possible (3)', 'Unlikely (2)', 'Rare (1)'],
            color_continuous_scale=[[0, "#22c55e"], [0.4, "#eab308"], [0.7, "#f97316"], [1, "#ef4444"]],
            aspect="auto"
        )
        fig_heat.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#94a3b8'),
            margin=dict(l=20, r=20, t=30, b=20),
            height=340
        )
        st.plotly_chart(fig_heat, use_container_width=True)

    # Probabilistic Quantiles and Top High-Risk Assets
    col_q, col_top_assets = st.columns([5, 6])
    with col_q:
        st.subheader("📊 Probabilistic Risk Quantiles (INR)")
        quantiles_df = pd.DataFrame({
            "Confidence Level": ["P10 (Best Case)", "P50 (Median Loss)", "P90 (Stress Test)", "P95 (VaR)", "P99 (Extreme Loss)"],
            "Annual Loss (₹ Lakhs)": [sim_results["p10"]/100000, sim_results["p50"]/100000, sim_results["p90"]/100000, sim_results["var_95"]/100000, sim_results["p99"]/100000]
        })
        fig_q = px.bar(
            quantiles_df,
            x="Confidence Level",
            y="Annual Loss (₹ Lakhs)",
            color="Annual Loss (₹ Lakhs)",
            color_continuous_scale="Viridis",
            text_auto='.1f'
        )
        fig_q.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,23,42,0.6)', font=dict(color='#94a3b8'), margin=dict(l=20, r=20, t=30, b=20), height=320)
        st.plotly_chart(fig_q, use_container_width=True)

    with col_top_assets:
        st.subheader("🚨 Top High-Risk Assets by Risk Score")
        top_asset_display = fair_metrics["asset_risk_df"].head(6).copy()
        top_asset_display["Asset Value"] = top_asset_display["Asset Value (INR)"].apply(format_inr)
        top_asset_display["Asset ALE"] = top_asset_display["Asset ALE (INR)"].apply(format_inr)
        st.dataframe(
            top_asset_display[["Asset ID", "Asset Name", "Criticality", "Risk Score", "Asset ALE", "Risk Level"]],
            use_container_width=True,
            height=320
        )

# ==========================================
# TAB 2: RISK ANALYSIS & EXPLAINABILITY
# ==========================================
with tab_analysis:
    st.subheader("🔍 Asset-Level Risk Deep-Dive & AI Explainability")
    st.markdown("Clear, transparent decomposition of primary risk drivers for every asset in your enterprise.")

    selected_asset_id = st.selectbox(
        "Select Asset to Inspect:",
        options=st.session_state.assets_df["asset_id"].tolist(),
        format_func=lambda x: f"{x} - {st.session_state.assets_df[st.session_state.assets_df['asset_id']==x]['asset_name'].values[0]}"
    )

    asset_detail = fair_metrics["asset_risk_df"][fair_metrics["asset_risk_df"]["Asset ID"] == selected_asset_id].iloc[0]
    raw_asset = st.session_state.assets_df[st.session_state.assets_df["asset_id"] == selected_asset_id].iloc[0]
    
    col_d1, col_d2 = st.columns([5, 6])
    with col_d1:
        st.markdown(f"""
        <div class="highlight-box">
            <h4 style="color: #38bdf8; margin-bottom: 0.8rem;">🏛️ {raw_asset['asset_name']} ({raw_asset['asset_id']})</h4>
            <p><strong>Asset Type:</strong> {raw_asset['asset_type']} | <strong>Location:</strong> {raw_asset['location']}</p>
            <p><strong>Valuation:</strong> <span style="color: #38bdf8; font-weight: 700;">{format_inr(raw_asset['asset_value'])}</span></p>
            <p><strong>Business Criticality:</strong> {raw_asset['criticality']} / 5 ({raw_asset['business_importance']})</p>
            <p><strong>Internet Exposure:</strong> {raw_asset['internet_exposure']}</p>
            <p><strong>Data Sensitivity:</strong> {raw_asset['data_sensitivity']}</p>
            <p><strong>Single Loss Expectancy (SLE):</strong> <span style="color: #f87171; font-weight: 700;">{format_inr(asset_detail['SLE (INR)'])}</span></p>
            <p><strong>Annualized Loss Expectancy (ALE):</strong> <span style="color: #f87171; font-weight: 700;">{format_inr(asset_detail['Asset ALE (INR)'])}</span></p>
        </div>
        """, unsafe_allow_html=True)

    with col_d2:
        st.markdown(f"#### 🧠 Why is this asset rated **{asset_detail['Risk Level']}** ({asset_detail['Risk Score']}/100)?")
        st.caption(asset_detail["Explanation"])
        
        factors_df = pd.DataFrame({
            "Risk Factor": ["CVSS Vulnerability Severity", "Asset Business Criticality", "Internet / Attack Surface", "Security Control Gap"],
            "Contribution Score": [asset_detail["Factor_CVSS"], asset_detail["Factor_Criticality"], asset_detail["Factor_Exposure"], asset_detail["Factor_ControlGap"]]
        })
        fig_exp = px.bar(
            factors_df,
            x="Contribution Score",
            y="Risk Factor",
            orientation="h",
            color="Contribution Score",
            color_continuous_scale="Reds",
            text_auto=True
        )
        fig_exp.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,23,42,0.6)', font=dict(color='#94a3b8'), yaxis=dict(autorange="reversed"), margin=dict(t=20, b=20, l=20, r=20), height=260)
        st.plotly_chart(fig_exp, use_container_width=True)

    # Associated Active CVEs for selected asset
    st.markdown("#### ⚡ Active Vulnerabilities on this Asset")
    asset_cves = st.session_state.vulns_df[st.session_state.vulns_df["affected_asset"] == selected_asset_id]
    if len(asset_cves) > 0:
        st.dataframe(asset_cves[["cve_id", "vulnerability_name", "cvss_score", "severity", "patch_status", "public_exploit", "kev_status"]], use_container_width=True)
    else:
        st.info("No active unpatched vulnerabilities associated with this asset.")

# ==========================================
# TAB 3: INVESTMENT OPTIMIZER (PuLP MILP)
# ==========================================
with tab_opt:
    st.subheader("💼 Security Investment & Budget Optimization Engine (MILP)")
    st.markdown("Mathematical 0-1 Knapsack Mixed-Integer Linear Programming solves for the optimal combination of controls that maximizes financial risk reduction within your allocated budget.")

    opt_result = optimize_security_investments(
        st.session_state.controls_df,
        budget_limit=st.session_state.budget_limit,
        current_ale=fair_metrics["residual_ale"]
    )
    
    o1, o2, o3, o4 = st.columns(4)
    with o1:
        st.markdown(render_kpi_card("Allocated Budget", format_inr(st.session_state.budget_limit), color_class="val-cyan", subtext="User-defined limit"), unsafe_allow_html=True)
    with o2:
        st.markdown(render_kpi_card("Optimal Total Spend", format_inr(opt_result['total_spend']), color_class="val-green", subtext=f"{(opt_result['total_spend']/st.session_state.budget_limit)*100:.1f}% Budget Utilized"), unsafe_allow_html=True)
    with o3:
        st.markdown(render_kpi_card("Total Risk Mitigated", format_inr(opt_result['total_risk_reduced']), delta=f"{opt_result['roi_percentage']}% Net ROI", color_class="val-purple", subtext=f"{opt_result['risk_reduction_pct']}% Risk Reduction"), unsafe_allow_html=True)
    with o4:
        st.markdown(render_kpi_card("Post-Optimization ALE", format_inr(opt_result['residual_ale_after_optimization']), color_class="val-cyan", subtext="Optimized Future Risk"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_rec, col_frontier = st.columns([6, 6])
    with col_rec:
        st.markdown("#### ✅ Recommended Security Control Portfolio")
        rec_disp = opt_result["selected_controls_df"].copy()
        rec_disp["Implementation Cost"] = rec_disp["implementation_cost"].apply(format_inr)
        rec_disp["Maintenance Cost"] = rec_disp["maintenance_cost"].apply(format_inr)
        rec_disp["Risk Reduction Value"] = rec_disp["risk_reduction_value"].apply(format_inr)
        st.dataframe(
            rec_disp[["control_id", "control_name", "category", "Implementation Cost", "Risk Reduction Value", "effectiveness", "coverage"]],
            use_container_width=True
        )

        if len(opt_result["unselected_controls_df"]) > 0:
            with st.expander("🔻 Unfunded / Excluded Controls (Exceeds Current Budget)"):
                unfunded_disp = opt_result["unselected_controls_df"].copy()
                unfunded_disp["Cost"] = unfunded_disp["implementation_cost"].apply(format_inr)
                unfunded_disp["Potential Risk Reduction"] = unfunded_disp["risk_reduction_value"].apply(format_inr)
                st.dataframe(unfunded_disp[["control_id", "control_name", "Cost", "Potential Risk Reduction"]], use_container_width=True)

    with col_frontier:
        st.markdown("#### 📉 Security Investment Efficient Frontier Curve")
        frontier_df = opt_result["frontier_df"]
        fig_front = px.line(
            frontier_df,
            x="Budget (INR)",
            y="Max Risk Reduction (INR)",
            markers=True,
            title="Diminishing Returns: Budget Investment vs Risk Reduction",
            hover_data=["Actual Spend (INR)", "Residual ALE (INR)", "Controls Count"]
        )
        fig_front.add_vline(x=st.session_state.budget_limit, line_dash="dash", line_color="#38bdf8", annotation_text="Your Budget")
        fig_front.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,23,42,0.6)', font=dict(color='#94a3b8'), margin=dict(l=20, r=20, t=40, b=20), height=340)
        st.plotly_chart(fig_front, use_container_width=True)

# ==========================================
# TAB 4: AI/ML RISK ENGINE
# ==========================================
with tab_ml:
    st.subheader("🧠 Machine Learning Continuous Risk Predictor (Random Forest / Regressor)")
    st.caption("Supervised ML model trained on synthetic multivariate telemetry to predict continuous financial cyber risk losses and breach probabilities.")

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(render_kpi_card("Model Architecture", ml_engine.model_type, color_class="val-purple", subtext="Supervised ML Regressor"), unsafe_allow_html=True)
    with m2:
        st.markdown(render_kpi_card("R² Accuracy Score", f"{ml_engine.metrics['R2']:.3f}", color_class="val-green", subtext="Test Set Variance Fit"), unsafe_allow_html=True)
    with m3:
        st.markdown(render_kpi_card("RMSE", format_inr(ml_engine.metrics['RMSE']), color_class="val-cyan", subtext="Root Mean Squared Error"), unsafe_allow_html=True)
    with m4:
        st.markdown(render_kpi_card("Mean Absolute Error", format_inr(ml_engine.metrics['MAE']), color_class="val-amber", subtext="Average prediction delta"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_fi, col_sb = st.columns([5, 6])
    with col_fi:
        st.markdown("#### 📊 ML Feature Importance (Risk Drivers)")
        fig_fi = px.bar(
            ml_engine.feature_importances_.head(10),
            x="Importance",
            y="Feature",
            orientation="h",
            color="Importance",
            color_continuous_scale="Tealgrn"
        )
        fig_fi.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,23,42,0.6)', font=dict(color='#94a3b8'), yaxis=dict(autorange="reversed"), margin=dict(t=20, b=20, l=20, r=20), height=380)
        st.plotly_chart(fig_fi, use_container_width=True)

    with col_sb:
        st.markdown("#### 🧪 Interactive What-If Scenario Sandbox")
        sb_col1, sb_col2 = st.columns(2)
        with sb_col1:
            sb_asset_val = st.number_input("Asset Valuation (INR)", value=35000000, step=1000000)
            sb_asset_crit = st.slider("Asset Criticality (1-5)", 1, 5, 5)
            sb_internet = st.selectbox("Internet Exposed?", ["Yes (1)", "No (0)"])
            sb_users = st.number_input("Active Users", value=150000, step=10000)
            sb_cvss = st.slider("CVSS v3.1 Score", 1.0, 10.0, 9.8, 0.1)
        with sb_col2:
            sb_exploit = st.slider("Exploitability (0-1)", 0.1, 1.0, 0.95, 0.05)
            sb_weaponized = st.selectbox("Weaponized Exploit?", ["Yes (1)", "No (0)"])
            sb_patch = st.selectbox("Patch Status", ["Unpatched (0)", "In-Progress (0.5)", "Patched (1.0)"])
            sb_threat_freq = st.slider("Threat Frequency (Events/Yr)", 1.0, 50.0, 18.0)
            sb_threat_intel = st.slider("Threat Intel Score (0-100)", 0, 100, 92)

        sb_control_eff = st.slider("Control Effectiveness (%)", 10, 100, 85)
        sb_control_cov = st.slider("Control Coverage (%)", 10, 100, 90)

        pred_payload = {
            "Asset_Value": sb_asset_val,
            "Asset_Criticality": sb_asset_crit,
            "Internet_Exposed": 1 if "Yes" in sb_internet else 0,
            "Num_Users": sb_users,
            "Data_Sensitivity": 4,
            "CVSS_Score": sb_cvss,
            "Exploitability": sb_exploit,
            "Vuln_Age_Days": 120,
            "Weaponized_Exploit": 1 if "Yes" in sb_weaponized else 0,
            "Patch_Status_Score": 0.0 if "Unpatched" in sb_patch else (0.5 if "In-Progress" in sb_patch else 1.0),
            "Threat_Frequency": sb_threat_freq,
            "Threat_Intel_Score": sb_threat_intel,
            "Threat_Severity": 4,
            "Control_Effectiveness": sb_control_eff,
            "Control_Coverage": sb_control_cov,
            "Prevention_Capability": 85.0,
            "Detection_Capability": 85.0
        }
        pred_loss, pred_prob = ml_engine.predict(pred_payload)

        st.markdown(f"""
        <div class="highlight-box" style="text-align: center;">
            <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase;">Predicted Incident Probability</div>
            <div style="font-size: 2.2rem; font-weight: 800; color: #f87171; font-family: 'JetBrains Mono';">{pred_prob*100:.1f}%</div>
            <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; margin-top: 0.5rem;">Predicted Annual Cyber Loss Exposure</div>
            <div style="font-size: 2.0rem; font-weight: 800; color: #38bdf8; font-family: 'JetBrains Mono';">{format_inr(pred_loss)}</div>
        </div>
        """, unsafe_allow_html=True)

# ==========================================
# TAB 5: ALERT CENTER
# ==========================================
with tab_alerts:
    st.subheader(f"🚨 Continuous Security Alert Center ({len(live_alerts_df)} Active)")
    st.caption("Real-time notifications generated by continuous risk telemetry, unpatched KEV CVEs, and coverage gaps.")

    alert_filter = st.selectbox("Filter by Severity:", ["All", "CRITICAL", "HIGH", "WARNING", "INFO"])
    filtered_alerts = live_alerts_df if alert_filter == "All" else live_alerts_df[live_alerts_df["severity"] == alert_filter]

    for _, alert in filtered_alerts.iterrows():
        badge_class = "badge-critical" if alert["severity"] == "CRITICAL" else ("badge-high" if alert["severity"] == "HIGH" else "badge-medium")
        st.markdown(f"""
        <div class="highlight-box" style="border-left: 4px solid {'#ef4444' if alert['severity']=='CRITICAL' else ('#f97316' if alert['severity']=='HIGH' else '#eab308')};">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span class="cyber-badge {badge_class}">{alert['severity']}</span>
                <span style="font-size: 0.75rem; color: #64748b;">{alert['created_at']}</span>
            </div>
            <h5 style="margin-top: 0.5rem; color: #e2e8f0;">{alert['title']}</h5>
            <p style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.3rem;">{alert['message']}</p>
            <span style="font-size: 0.75rem; color: #38bdf8;">Related Asset: {alert['related_asset']} | Risk Score: {alert['risk_score']:.1f}</span>
        </div>
        """, unsafe_allow_html=True)

# ==========================================
# TAB 6: INCIDENT HISTORY
# ==========================================
with tab_incidents:
    st.subheader("📝 Historical Security Incidents & Loss Telemetry")
    st.caption("20 recorded enterprise breach events, downtime impacts, and root-cause analyses.")

    inc_disp = st.session_state.incidents_df.copy()
    total_loss_inc = inc_disp["financial_loss"].sum()
    total_downtime = inc_disp["downtime_hours"].sum()

    i1, i2, i3 = st.columns(3)
    with i1:
        st.markdown(render_kpi_card("Total Historical Loss", format_inr(total_loss_inc), color_class="val-red", subtext="Past 12 Months"), unsafe_allow_html=True)
    with i2:
        st.markdown(render_kpi_card("Total Downtime", f"{total_downtime:.1f} Hours", color_class="val-amber", subtext="Cumulative operational disruption"), unsafe_allow_html=True)
    with i3:
        st.markdown(render_kpi_card("Recorded Incidents", str(len(inc_disp)), color_class="val-cyan", subtext="Resolved & Closed"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    inc_disp["Financial Loss"] = inc_disp["financial_loss"].apply(format_inr)
    st.dataframe(inc_disp[["incident_id", "date", "incident_type", "affected_asset", "Financial Loss", "downtime_hours", "root_cause", "severity"]], use_container_width=True)

# ==========================================
# TAB 7: ASSET & SECURITY TELEMETRY (CRUD)
# ==========================================
with tab_assets:
    st.subheader("🏛️ Enterprise Parameter Telemetry & Data Management")
    sub_tab_a, sub_tab_v, sub_tab_t, sub_tab_c = st.tabs(["🏛️ Assets (20)", "⚡ Vulnerabilities (30)", "🎯 Threat Actors (15)", "🔒 Controls (10)"])

    with sub_tab_a:
        st.markdown("##### 🏛️ Enterprise Assets (CRUD)")
        edited_a = st.data_editor(st.session_state.assets_df, num_rows="dynamic", use_container_width=True)
        if not edited_a.equals(st.session_state.assets_df):
            st.session_state.assets_df = edited_a
            save_dataframe_to_db("assets", edited_a)
            st.success("Assets synchronized to SQLite!")
            st.rerun()

    with sub_tab_v:
        st.markdown("##### ⚡ Vulnerability Tracking (CRUD)")
        edited_v = st.data_editor(st.session_state.vulns_df, num_rows="dynamic", use_container_width=True)
        if not edited_v.equals(st.session_state.vulns_df):
            st.session_state.vulns_df = edited_v
            save_dataframe_to_db("vulnerabilities", edited_v)
            st.success("Vulnerabilities synchronized to SQLite!")
            st.rerun()

    with sub_tab_t:
        st.markdown("##### 🎯 Threat Actors & Scenarios (CRUD)")
        edited_t = st.data_editor(st.session_state.threats_df, num_rows="dynamic", use_container_width=True)
        if not edited_t.equals(st.session_state.threats_df):
            st.session_state.threats_df = edited_t
            save_dataframe_to_db("threats", edited_t)
            st.success("Threat catalog synchronized to SQLite!")
            st.rerun()

    with sub_tab_c:
        st.markdown("##### 🔒 Security Control Parameters (CRUD)")
        edited_c = st.data_editor(st.session_state.controls_df, num_rows="dynamic", use_container_width=True)
        if not edited_c.equals(st.session_state.controls_df):
            st.session_state.controls_df = edited_c
            save_dataframe_to_db("security_controls", edited_c)
            st.success("Security controls synchronized to SQLite!")
            st.rerun()

# ==========================================
# TAB 8: MITRE ATT&CK & THREAT INTEL
# ==========================================
with tab_mitre:
    st.subheader("🌐 Threat Intelligence & MITRE ATT&CK Alignment")
    
    st.markdown("#### 🔍 Live NVD CVE Intelligence Lookup")
    cve_q_col, cve_b_col = st.columns([5, 1])
    with cve_q_col:
        cve_q = st.text_input("Enter CVE Identifier:", value="CVE-2023-34362")
    with cve_b_col:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        cve_btn = st.button("Query NVD API", use_container_width=True)

    if cve_btn and cve_q:
        with st.spinner("Fetching CVE telemetry..."):
            info = query_nvd_cve(cve_q)
            st.info(f"**{info['cve_id']}** ({info['severity']} | CVSS {info['cvss_score']} | Attack Vector: {info['attack_vector']} | Source: {info['source']})\n\n{info['description']}")

    st.markdown("#### 🛡️ MITRE ATT&CK Enterprise Tactical Matrix Mapping")
    st.dataframe(pd.DataFrame(get_mitre_attack_matrix()), use_container_width=True)

# ==========================================
# TAB 9: EXECUTIVE REPORT & EXPORT
# ==========================================
with tab_reports:
    st.subheader("📄 Board-Ready Executive Cyber Risk & Investment Report")
    st.caption("Printable comprehensive summary of financial risk quantification, top vulnerabilities, and recommended investments.")

    st.markdown(f"""
    <div class="highlight-box">
        <h3 style="color: #38bdf8; margin-bottom: 0.5rem;">CyberRisk AI — Executive Risk Assessment</h3>
        <p style="font-size: 0.85rem; color: #94a3b8;">Report Date: {datetime.now().strftime("%B %d, %Y")} | Target Organization: Enterprise Financial Services</p>
        <hr style="border-color: rgba(255,255,255,0.1);">
        <p><strong>Total Monitored Asset Value:</strong> {format_inr(fair_metrics['total_asset_value'])} across 20 critical systems.</p>
        <p><strong>Inherent Annual Loss Expectancy (ALE):</strong> {format_inr(fair_metrics['inherent_ale'])}</p>
        <p><strong>Current Residual ALE:</strong> {format_inr(fair_metrics['residual_ale'])} (Mitigated by active controls)</p>
        <p><strong>Value-at-Risk (VaR 95% Confidence):</strong> {format_inr(sim_results['var_95'])} annual worst-case loss.</p>
        <p><strong>Recommended Security Budget:</strong> {format_inr(st.session_state.budget_limit)}</p>
        <p><strong>Projected Risk Reduction:</strong> {format_inr(opt_result['total_risk_reduced'])} (ROI: {opt_result['roi_percentage']}%)</p>
        <p><strong>Post-Optimization Future Residual ALE:</strong> {format_inr(opt_result['residual_ale_after_optimization'])}</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("#### 📥 Export Telemetry Data")
    exp_col1, exp_col2, exp_col3 = st.columns(3)
    with exp_col1:
        st.download_button(
            label="Download Assets CSV",
            data=st.session_state.assets_df.to_csv(index=False),
            file_name="cyberrisk_assets.csv",
            mime="text/csv",
            use_container_width=True
        )
    with exp_col2:
        st.download_button(
            label="Download Risk Rankings CSV",
            data=fair_metrics["asset_risk_df"].to_csv(index=False),
            file_name="cyberrisk_asset_rankings.csv",
            mime="text/csv",
            use_container_width=True
        )
    with exp_col3:
        st.download_button(
            label="Download Recommended Controls CSV",
            data=opt_result["selected_controls_df"].to_csv(index=False),
            file_name="recommended_security_portfolio.csv",
            mime="text/csv",
            use_container_width=True
        )

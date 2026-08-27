import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import json

# Page Configuration
st.set_page_config(
    page_title="CyberRiskIQ - AI Cyber Risk Quantification & Investment Optimizer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Import internal modules
from utils.ui_components import CUSTOM_CSS, render_kpi_card
from models.database import initialize_session_state, reset_to_defaults
from models.fair_engine import calculate_deterministic_fair, run_monte_carlo_simulation
from models.ml_engine import CyberRiskMLEngine
from models.optimizer_engine import optimize_security_investments
from services.threat_intel import query_nvd_cve, get_mitre_attack_matrix

# Inject CSS
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Initialize Session State
initialize_session_state()

# Cache ML Model
@st.cache_resource
def load_ml_engine():
    return CyberRiskMLEngine(model_type="XGBoost")

ml_engine = load_ml_engine()

# Sidebar Controls
with st.sidebar:
    st.markdown('<div class="cyber-header" style="font-size: 1.4rem;">🛡️ CyberRiskIQ</div>', unsafe_allow_html=True)
    st.caption("AI-Powered Cyber Risk Quantification & Investment Optimization")
    st.divider()
    
    st.subheader("⚙️ Global Parameters")
    budget_input = st.slider(
        "Available Security Budget ($)",
        min_value=20000,
        max_value=1200000,
        value=int(st.session_state.budget_limit),
        step=10000,
        format="$%d"
    )
    st.session_state.budget_limit = budget_input
    
    mc_runs = st.select_slider(
        "Monte Carlo Iterations",
        options=[1000, 5000, 10000, 20000],
        value=st.session_state.mc_simulations
    )
    st.session_state.mc_simulations = mc_runs

    st.divider()
    if st.button("🔄 Reset Baseline Datasets", use_container_width=True):
        reset_to_defaults()
        st.success("Platform reset to default baseline datasets!")
        st.rerun()

    st.divider()
    st.caption("Framework Alignments:")
    st.markdown("• **FAIR (Factor Analysis of Info Risk)**\n• **NIST CSF & MITRE ATT&CK**\n• **CISA KEV & NVD API v2.0**\n• **MILP Optimization (PuLP)**")

# Compute Live FAIR & Monte Carlo Metrics
sim_results = run_monte_carlo_simulation(
    st.session_state.assets_df,
    st.session_state.vulns_df,
    st.session_state.threats_df,
    st.session_state.controls_df,
    num_simulations=st.session_state.mc_simulations
)
fair_metrics = sim_results["deterministic"]

# Main Header
st.markdown('<div class="cyber-header">AI-Powered Continuous Cyber Risk Quantification & Investment Optimization</div>', unsafe_allow_html=True)
st.markdown('<div class="cyber-subtitle">Real-time financial risk exposure modeling, probabilistic loss forecasting, and mathematical portfolio optimization</div>', unsafe_allow_html=True)

# Top Navigation Tabs
tab_exec, tab_opt, tab_ml, tab_assets, tab_vulns, tab_threats, tab_controls, tab_mitre = st.tabs([
    "📊 Executive Dashboard",
    "💼 Investment Optimizer",
    "🧠 AI/ML Risk Engine",
    "🏛️ Assets & Criticality",
    "⚡ Vulnerability Intelligence",
    "🎯 Threat Modeling",
    "🔒 Security Controls",
    "🌐 MITRE & Threat Intel"
])

# ==========================================
# TAB 1: EXECUTIVE DASHBOARD
# ==========================================
with tab_exec:
    # KPI Metrics Row
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.markdown(render_kpi_card("Total Portfolio Value", f"${fair_metrics['total_asset_value']:,.0f}", color_class="val-cyan", subtext="8 Monitored Assets"), unsafe_allow_html=True)
    with c2:
        st.markdown(render_kpi_card("Inherent Loss (ALE)", f"${fair_metrics['inherent_ale']:,.0f}", delta="Unmitigated", color_class="val-red", subtext="Without active controls"), unsafe_allow_html=True)
    with c3:
        st.markdown(render_kpi_card("Residual Loss (ALE)", f"${fair_metrics['residual_ale']:,.0f}", delta=f"-${fair_metrics['risk_reduction_achieved']:,.0f}", color_class="val-amber", subtext="With current controls"), unsafe_allow_html=True)
    with c4:
        st.markdown(render_kpi_card("VaR (95% Confidence)", f"${sim_results['var_95']:,.0f}", color_class="val-purple", subtext="Annual worst-case loss"), unsafe_allow_html=True)
    with c5:
        st.markdown(render_kpi_card("Enterprise Risk Index", f"{fair_metrics['enterprise_risk_index']} / 100", color_class="val-green" if fair_metrics['enterprise_risk_index'] < 40 else "val-amber", subtext="FAIR Normalized Score"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Charts Row 1: Loss Exceedance Curve (LEC) & Risk Heatmap
    col_lec, col_heatmap = st.columns([6, 5])
    
    with col_lec:
        st.subheader("📈 Loss Exceedance Curve (Monte Carlo 10k Runs)")
        lec_df = sim_results["lec_df"]
        fig_lec = go.Figure()
        fig_lec.add_trace(go.Scatter(
            x=lec_df["Exceedance_Probability (%)"],
            y=lec_df["Inherent_Loss ($)"],
            mode='lines',
            name='Inherent Risk (Unmitigated)',
            line=dict(color='#ef4444', width=2.5, dash='dot')
        ))
        fig_lec.add_trace(go.Scatter(
            x=lec_df["Exceedance_Probability (%)"],
            y=lec_df["Residual_Loss ($)"],
            mode='lines',
            name='Residual Risk (Current Controls)',
            line=dict(color='#38bdf8', width=3)
        ))
        fig_lec.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(15,23,42,0.6)',
            font=dict(color='#94a3b8'),
            xaxis=dict(title='Probability of Exceeding Loss (%)', gridcolor='rgba(255,255,255,0.08)'),
            yaxis=dict(title='Annual Financial Loss ($)', gridcolor='rgba(255,255,255,0.08)'),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=20, r=20, t=30, b=20),
            height=340
        )
        st.plotly_chart(fig_lec, use_container_width=True)

    with col_heatmap:
        st.subheader("🗺️ 5x5 Threat-Asset Risk Matrix")
        # Build 5x5 matrix
        heatmap_z = np.array([
            [12, 25, 45, 78, 95],
            [8,  18, 35, 65, 85],
            [5,  12, 28, 50, 70],
            [3,  7,  15, 30, 48],
            [1,  3,  8,  15, 25]
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

    # Charts Row 2: Probabilistic Percentiles & Asset Risk Ranking Table
    col_p, col_table = st.columns([5, 6])
    
    with col_p:
        st.subheader("📊 Probabilistic Risk Quantiles")
        quantiles_df = pd.DataFrame({
            "Confidence Level": ["P10 (Best Case)", "P50 (Median Expected)", "P90 (Stress Test)", "P95 (VaR)", "P99 (Extreme Loss)"],
            "Annual Loss ($)": [sim_results["p10"], sim_results["p50"], sim_results["p90"], sim_results["var_95"], sim_results["p99"]]
        })
        fig_bar = px.bar(
            quantiles_df,
            x="Confidence Level",
            y="Annual Loss ($)",
            color="Annual Loss ($)",
            color_continuous_scale="Viridis",
            text_auto='.2s'
        )
        fig_bar.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(15,23,42,0.6)',
            font=dict(color='#94a3b8'),
            margin=dict(l=20, r=20, t=30, b=20),
            height=320
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with col_table:
        st.subheader("🚨 Top High-Risk Assets by ALE")
        st.dataframe(
            fair_metrics["asset_risk_df"][["Asset ID", "Asset Name", "Criticality", "Active CVEs", "Asset ALE ($)", "Risk Level"]],
            use_container_width=True,
            height=320,
            column_config={
                "Asset ALE ($)": st.column_config.NumberColumn(format="$%d"),
                "Risk Level": st.column_config.TextColumn()
            }
        )

# ==========================================
# TAB 2: INVESTMENT OPTIMIZER (PuLP MILP)
# ==========================================
with tab_opt:
    st.subheader("💼 Security Investment & Budget Optimization Engine (MILP)")
    st.markdown("Uses **PuLP Mixed-Integer Linear Programming (0-1 Knapsack)** to compute the mathematically optimal set of cybersecurity controls that maximizes total risk reduction under your specific budget constraint.")
    
    opt_result = optimize_security_investments(
        st.session_state.controls_df,
        budget_limit=st.session_state.budget_limit,
        current_ale=fair_metrics["residual_ale"]
    )
    
    # Optimizer KPI Row
    o1, o2, o3, o4 = st.columns(4)
    with o1:
        st.markdown(render_kpi_card("Allocated Budget", f"${st.session_state.budget_limit:,.0f}", color_class="val-cyan", subtext="User Constraint"), unsafe_allow_html=True)
    with o2:
        st.markdown(render_kpi_card("Optimal Total Spend", f"${opt_result['total_spend']:,.0f}", color_class="val-green", subtext=f"{(opt_result['total_spend']/st.session_state.budget_limit)*100:.1f}% Budget Utilized"), unsafe_allow_html=True)
    with o3:
        st.markdown(render_kpi_card("Total Risk Mitigated", f"${opt_result['total_risk_reduced']:,.0f}", delta=f"{opt_result['roi_percentage']}% ROI", color_class="val-purple", subtext="Financial Loss Prevented"), unsafe_allow_html=True)
    with o4:
        st.markdown(render_kpi_card("Post-Optimization Residual ALE", f"${opt_result['residual_ale_after_optimization']:,.0f}", color_class="val-cyan", subtext="Optimized Future Risk"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    
    # Visualizing Optimization Results
    col_rec, col_frontier = st.columns([6, 6])
    
    with col_rec:
        st.markdown("#### ✅ Recommended Security Control Portfolio")
        st.caption("Controls selected by linear programming to maximize risk mitigation ROI:")
        st.dataframe(
            opt_result["selected_controls_df"][["Control ID", "Control Name", "Control Cost ($)", "Maintenance Cost ($)", "Risk Reduction ($)", "Control Effectiveness (%)"]],
            use_container_width=True,
            column_config={
                "Control Cost ($)": st.column_config.NumberColumn(format="$%d"),
                "Maintenance Cost ($)": st.column_config.NumberColumn(format="$%d"),
                "Risk Reduction ($)": st.column_config.NumberColumn(format="$%d")
            }
        )
        
        if len(opt_result["unselected_controls_df"]) > 0:
            with st.expander("🔻 Unfunded / Excluded Controls (Exceeds Current Budget)"):
                st.dataframe(
                    opt_result["unselected_controls_df"][["Control ID", "Control Name", "Control Cost ($)", "Risk Reduction ($)"]],
                    use_container_width=True,
                    column_config={
                        "Control Cost ($)": st.column_config.NumberColumn(format="$%d"),
                        "Risk Reduction ($)": st.column_config.NumberColumn(format="$%d")
                    }
                )

    with col_frontier:
        st.markdown("#### 📉 Security Investment Efficient Frontier Curve")
        frontier_df = opt_result["frontier_df"]
        fig_front = px.line(
            frontier_df,
            x="Budget ($)",
            y="Max Risk Reduction ($)",
            markers=True,
            title="Diminishing Returns: Budget Investment vs Total Risk Mitigated",
            hover_data=["Actual Spend ($)", "Residual ALE ($)", "Controls Count"]
        )
        fig_front.add_vline(x=st.session_state.budget_limit, line_dash="dash", line_color="#38bdf8", annotation_text="Your Budget")
        fig_front.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(15,23,42,0.6)',
            font=dict(color='#94a3b8'),
            xaxis=dict(gridcolor='rgba(255,255,255,0.08)'),
            yaxis=dict(gridcolor='rgba(255,255,255,0.08)'),
            margin=dict(l=20, r=20, t=40, b=20),
            height=340
        )
        st.plotly_chart(fig_front, use_container_width=True)

# ==========================================
# TAB 3: AI/ML RISK ENGINE
# ==========================================
with tab_ml:
    st.subheader("🧠 Machine Learning Cyber Risk Predictor (XGBoost / Gradient Boosting)")
    st.markdown("Trained on multi-variate continuous telemetry across asset exposure, vulnerability exploitability, threat intelligence scores, and control attenuation.")

    # Model Performance KPIs
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(render_kpi_card("Model Architecture", ml_engine.model_type, color_class="val-purple", subtext="Supervised Regressor"), unsafe_allow_html=True)
    with m2:
        st.markdown(render_kpi_card("R² Accuracy Score", f"{ml_engine.metrics['R2']:.3f}", color_class="val-green", subtext="Test Set Fit"), unsafe_allow_html=True)
    with m3:
        st.markdown(render_kpi_card("RMSE", f"${ml_engine.metrics['RMSE']:,.0f}", color_class="val-cyan", subtext="Root Mean Squared Error"), unsafe_allow_html=True)
    with m4:
        st.markdown(render_kpi_card("Mean Absolute Error (MAE)", f"${ml_engine.metrics['MAE']:,.0f}", color_class="val-amber", subtext="Average prediction delta"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    
    col_feat, col_sandbox = st.columns([5, 6])
    
    with col_feat:
        st.markdown("#### 📊 ML Feature Importance (Risk Drivers)")
        fig_fi = px.bar(
            ml_engine.feature_importances_.head(10),
            x="Importance",
            y="Feature",
            orientation="h",
            color="Importance",
            color_continuous_scale="Tealgrn"
        )
        fig_fi.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(15,23,42,0.6)',
            font=dict(color='#94a3b8'),
            yaxis=dict(autorange="reversed"),
            margin=dict(l=20, r=20, t=30, b=20),
            height=380
        )
        st.plotly_chart(fig_fi, use_container_width=True)

    with col_sandbox:
        st.markdown("#### 🧪 Interactive What-If Risk Sandbox")
        st.caption("Simulate real-time ML risk quantification for custom scenario parameters:")
        
        sb_col1, sb_col2 = st.columns(2)
        with sb_col1:
            sb_asset_val = st.number_input("Asset Value ($)", value=2500000, step=100000)
            sb_asset_crit = st.slider("Asset Criticality (1-5)", 1, 5, 4)
            sb_internet = st.selectbox("Internet Exposed?", ["Yes (1)", "No (0)"])
            sb_users = st.number_input("Active Users", value=50000, step=5000)
            sb_data_sens = st.slider("Data Sensitivity (1-4)", 1, 4, 3)
            sb_cvss = st.slider("CVSS v3.1 Score", 1.0, 10.0, 9.4, 0.1)
        with sb_col2:
            sb_exploit = st.slider("Exploitability Score (0-1)", 0.1, 1.0, 0.90, 0.05)
            sb_vuln_age = st.slider("Vulnerability Age (Days)", 1, 730, 90)
            sb_weaponized = st.selectbox("Weaponized Exploit in Wild?", ["Yes (1)", "No (0)"])
            sb_patch = st.selectbox("Patch Status", ["Unpatched (0)", "In-Progress (0.5)", "Patched (1.0)"])
            sb_threat_freq = st.slider("Threat Frequency (Events/Yr)", 1.0, 50.0, 15.0)
            sb_threat_intel = st.slider("Threat Intel Score (0-100)", 0, 100, 85)

        sb_control_eff = st.slider("Security Control Effectiveness (%)", 10, 100, 85)
        sb_control_cov = st.slider("Control Coverage (%)", 10, 100, 90)

        # Build prediction payload
        pred_payload = {
            "Asset_Value": sb_asset_val,
            "Asset_Criticality": sb_asset_crit,
            "Internet_Exposed": 1 if "Yes" in sb_internet else 0,
            "Num_Users": sb_users,
            "Data_Sensitivity": sb_data_sens,
            "CVSS_Score": sb_cvss,
            "Exploitability": sb_exploit,
            "Vuln_Age_Days": sb_vuln_age,
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
        
        ml_prediction = ml_engine.predict(pred_payload)
        st.markdown(f"""
        <div class="highlight-box" style="text-align: center;">
            <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase;">Predicted Annual Cyber Loss Exposure</div>
            <div style="font-size: 2.2rem; font-weight: 800; color: #f87171; font-family: 'JetBrains Mono';">${ml_prediction:,.2f}</div>
            <div style="font-size: 0.78rem; color: #38bdf8; margin-top: 0.2rem;">Generated via {ml_engine.model_type} Regression Inference</div>
        </div>
        """, unsafe_allow_html=True)

# ==========================================
# TAB 4: ASSETS & CRITICALITY
# ==========================================
with tab_assets:
    st.subheader("🏛️ Asset Inventory & Criticality Parameters")
    st.caption("Manage enterprise assets with full financial, operational, and exposure attributes.")

    # Asset Data Editor
    edited_assets = st.data_editor(
        st.session_state.assets_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "Asset Value ($)": st.column_config.NumberColumn(format="$%d"),
            "Asset Criticality": st.column_config.NumberColumn(min_value=1, max_value=5, step=1),
            "Internet Exposure": st.column_config.SelectboxColumn(options=["Yes (Public)", "Yes (Remote Work)", "Yes (Restricted mTLS)", "Yes (SaaS Public)", "No (Internal VPC)", "No (Corporate LAN)", "No (Private Subnet)", "No (Air-gapped Zone)"])
        }
    )
    if not edited_assets.equals(st.session_state.assets_df):
        st.session_state.assets_df = edited_assets
        st.success("Asset inventory updated! Live risk metrics recalculated.")
        st.rerun()

    # Asset Value & Criticality Visuals
    c_a1, c_a2 = st.columns(2)
    with c_a1:
        fig_asset_pie = px.pie(
            st.session_state.assets_df,
            values="Asset Value ($)",
            names="Asset Type",
            title="Portfolio Value by Asset Type",
            hole=0.45,
            color_discrete_sequence=px.colors.sequential.Plasma
        )
        fig_asset_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', font=dict(color='#94a3b8'), margin=dict(t=40, b=20, l=20, r=20), height=300)
        st.plotly_chart(fig_asset_pie, use_container_width=True)

    with c_a2:
        fig_asset_crit = px.bar(
            st.session_state.assets_df,
            x="Asset ID",
            y="Asset Value ($)",
            color="Asset Criticality",
            title="Asset Valuation vs Criticality Level",
            color_continuous_scale="Reds"
        )
        fig_asset_crit.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,23,42,0.6)', font=dict(color='#94a3b8'), margin=dict(t=40, b=20, l=20, r=20), height=300)
        st.plotly_chart(fig_asset_crit, use_container_width=True)

# ==========================================
# TAB 5: VULNERABILITY INTELLIGENCE & CVEs
# ==========================================
with tab_vulns:
    st.subheader("⚡ Vulnerability Tracking & Live NVD CVE Intelligence")
    
    # Live CVE Lookup tool
    st.markdown("#### 🔍 Live NVD / CISA KEV CVE Lookup")
    cve_query_col, cve_btn_col = st.columns([5, 1])
    with cve_query_col:
        cve_query = st.text_input("Enter CVE Identifier (e.g. CVE-2023-34362, CVE-2021-44228, CVE-2024-21762)", value="CVE-2023-34362")
    with cve_btn_col:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        fetch_cve_btn = st.button("Query NVD API", use_container_width=True)

    if fetch_cve_btn and cve_query:
        with st.spinner("Querying NVD API v2.0..."):
            cve_info = query_nvd_cve(cve_query)
            st.info(f"**{cve_info['cve_id']}** ({cve_info['severity']} Severity | CVSS {cve_info['cvss_score']} | Attack Vector: {cve_info['attack_vector']} | Source: {cve_info['source']})\n\n{cve_info['description']}")

    st.markdown("#### 📋 Active Enterprise Vulnerabilities Registry")
    edited_vulns = st.data_editor(
        st.session_state.vulns_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "CVSS Score": st.column_config.NumberColumn(min_value=0.0, max_value=10.0, step=0.1),
            "Patch Status": st.column_config.SelectboxColumn(options=["Unpatched", "In-Progress", "Patched"]),
            "Vulnerability Severity": st.column_config.SelectboxColumn(options=["Critical", "High", "Medium", "Low"])
        }
    )
    if not edited_vulns.equals(st.session_state.vulns_df):
        st.session_state.vulns_df = edited_vulns
        st.success("Vulnerability registry updated!")
        st.rerun()

# ==========================================
# TAB 6: THREAT MODELING
# ==========================================
with tab_threats:
    st.subheader("🎯 Threat Actor Catalog & Attack Probability Parameters")
    st.caption("Quantifies adversary capabilities, threat frequency, historical attack telemetry, and exploit availability.")

    edited_threats = st.data_editor(
        st.session_state.threats_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "Threat Frequency (Events/Yr)": st.column_config.NumberColumn(step=0.5),
            "Probability of Attack": st.column_config.NumberColumn(min_value=0.0, max_value=1.0, step=0.05),
            "Threat Intelligence Score": st.column_config.NumberColumn(min_value=0, max_value=100)
        }
    )
    if not edited_threats.equals(st.session_state.threats_df):
        st.session_state.threats_df = edited_threats
        st.success("Threat catalog updated!")
        st.rerun()

    c_t1, c_t2 = st.columns(2)
    with c_t1:
        fig_threat_scatter = px.scatter(
            st.session_state.threats_df,
            x="Threat Frequency (Events/Yr)",
            y="Probability of Attack",
            size="Historical Attack Count",
            color="Threat Severity",
            hover_name="Threat Type",
            title="Threat Frequency vs Probability of Attack",
            color_discrete_map={"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"}
        )
        fig_threat_scatter.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,23,42,0.6)', font=dict(color='#94a3b8'), margin=dict(t=40, b=20, l=20, r=20), height=320)
        st.plotly_chart(fig_threat_scatter, use_container_width=True)

    with c_t2:
        fig_threat_intel = px.bar(
            st.session_state.threats_df,
            x="Threat Type",
            y="Threat Intelligence Score",
            color="Threat Intelligence Score",
            title="Threat Intelligence Severity Index",
            color_continuous_scale="Magma"
        )
        fig_threat_intel.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,23,42,0.6)', font=dict(color='#94a3b8'), margin=dict(t=40, b=20, l=20, r=20), height=320)
        st.plotly_chart(fig_threat_intel, use_container_width=True)

# ==========================================
# TAB 7: SECURITY CONTROLS & ROI
# ==========================================
with tab_controls:
    st.subheader("🔒 Security Control Library & Mitigation Telemetry")
    st.caption("Configure implementation costs, prevention/detection effectiveness, and estimated risk reductions.")

    edited_controls = st.data_editor(
        st.session_state.controls_df,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "Control Cost ($)": st.column_config.NumberColumn(format="$%d"),
            "Maintenance Cost ($)": st.column_config.NumberColumn(format="$%d"),
            "Risk Reduction ($)": st.column_config.NumberColumn(format="$%d"),
            "Implementation Status": st.column_config.SelectboxColumn(options=["Active", "Planned", "Under Review", "Deprecated"])
        }
    )
    if not edited_controls.equals(st.session_state.controls_df):
        st.session_state.controls_df = edited_controls
        st.success("Security control parameters updated!")
        st.rerun()

    # Cost vs Risk Reduction Scatter
    fig_ctrl_roi = px.scatter(
        st.session_state.controls_df,
        x="Control Cost ($)",
        y="Risk Reduction ($)",
        size="Control Effectiveness (%)",
        color="Implementation Status",
        hover_name="Control Name",
        title="Control Acquisition Cost vs Estimated Risk Reduction Value ($)",
        color_discrete_map={"Active": "#22c55e", "Planned": "#38bdf8", "Under Review": "#facc15"}
    )
    fig_ctrl_roi.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,23,42,0.6)', font=dict(color='#94a3b8'), margin=dict(t=40, b=20, l=20, r=20), height=340)
    st.plotly_chart(fig_ctrl_roi, use_container_width=True)

# ==========================================
# TAB 8: MITRE ATT&CK & THREAT INTEL
# ==========================================
with tab_mitre:
    st.subheader("🌐 MITRE ATT&CK Tactical Defense Mapping")
    st.caption("Tactical coverage across adversary tactics, techniques, and mapped enterprise security controls.")
    
    mitre_data = get_mitre_attack_matrix()
    st.dataframe(pd.DataFrame(mitre_data), use_container_width=True)

    st.markdown("""
    <div class="highlight-box">
        <h5 style="color: #38bdf8; margin-bottom: 0.5rem;">🔗 Continuous Threat Intelligence Integrations</h5>
        <p style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 0.4rem;">
            CyberRiskIQ continuously aggregates signals from <strong>NVD (NIST)</strong>, <strong>CISA Known Exploited Vulnerabilities (KEV) Catalog</strong>, and <strong>MITRE ATT&CK Enterprise Matrix</strong> to calibrate Threat Event Frequencies and Attenuation Factors.
        </p>
    </div>
    """, unsafe_allow_html=True)

# 🛡️ CyberRiskIQ: AI-Powered Continuous Cyber Risk Quantification & Investment Optimization Platform

CyberRiskIQ is an end-to-end cybersecurity risk quantification (CRQ) and security investment optimization platform built in Python & Streamlit.

## 🚀 Key Features

1. **FAIR & Monte Carlo Risk Engine**
   - Implements the **Factor Analysis of Information Risk (FAIR)** framework.
   - Runs 1,000 to 20,000 Monte Carlo probabilistic simulations to generate **Loss Exceedance Curves (LEC)**.
   - Computes **Annualized Loss Expectancy (ALE)**, **Single Loss Expectancy (SLE)**, and **Value-at-Risk (VaR 95% / 99%)**.

2. **Mathematical Investment Optimizer (PuLP MILP)**
   - Formulates the 0-1 Knapsack / Mixed-Integer Linear Programming security control selection problem.
   - Maximizes financial risk mitigation and protection effectiveness within a user-defined budget.
   - Produces the **Security Investment Efficient Frontier Curve**.

3. **Machine Learning Predictive Risk Engine (XGBoost / Scikit-Learn)**
   - Multi-variate risk regression modeling based on asset exposure, CVSS v3.1, weaponized exploit status, threat actor capabilities, and security control coverage.
   - Feature importance rankings (identifying primary enterprise risk drivers).
   - Interactive what-if risk prediction sandbox.

4. **Continuous Parameter Telemetry**
   - **1. Asset Parameters**: Asset ID, Asset Type, Asset Value, Asset Criticality, Business Importance, Internet Exposure, Data Sensitivity, Number of Users, Location, System Availability Requirement.
   - **2. Vulnerability Parameters**: CVE ID, CVSS Score, Vulnerability Severity, Exploitability, Vulnerability Age, Patch Status, Public Exploit Availability, Affected Asset, Attack Vector, Attack Complexity.
   - **3. Threat Parameters**: Threat Type, Threat Frequency, Threat Severity, Attack Vector, Threat Actor, Historical Attack Count, Exploit Availability, Threat Intelligence Score, Probability of Attack.
   - **4. Security Control Parameters**: Control Name, Control Cost, Control Effectiveness, Coverage Percentage, Implementation Status, Maintenance Cost, Risk Reduction, Detection Capability, Prevention Capability.

5. **Threat Intelligence & Tactical Mapping**
   - Live querying of the **NVD (NIST) API v2.0** and offline CISA Known Exploited Vulnerabilities (KEV) cache.
   - **MITRE ATT&CK Enterprise Matrix** alignment.

---

## 💻 How to Run Locally

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Launch Streamlit Application**:
   ```bash
   streamlit run app.py
   ```

3. Open your browser at `http://localhost:8501`.

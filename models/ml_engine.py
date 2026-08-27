import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import r2_score, mean_squared_error, mean_absolute_error

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except Exception:
    XGBOOST_AVAILABLE = False

def generate_synthetic_training_data(n_samples: int = 2500) -> pd.DataFrame:
    """
    Generates a realistic synthetic dataset in Indian Rupees (INR) for ML model training.
    """
    np.random.seed(1337)
    
    asset_val = np.random.uniform(500000, 80000000, n_samples)  # ₹5 Lakhs to ₹8 Crores
    asset_crit = np.random.randint(1, 6, n_samples)
    is_internet_exposed = np.random.binomial(1, 0.55, n_samples)
    num_users = np.random.randint(50, 1000000, n_samples)
    data_sensitivity = np.random.randint(1, 5, n_samples)
    
    cvss_score = np.random.uniform(2.0, 10.0, n_samples)
    exploitability = np.random.uniform(0.1, 1.0, n_samples)
    vuln_age_days = np.random.uniform(5, 900, n_samples)
    weaponized_exploit = np.random.binomial(1, 0.40, n_samples)
    patch_status = np.random.choice([0, 0.5, 1.0], size=n_samples, p=[0.35, 0.25, 0.40])
    
    threat_freq = np.random.uniform(1.0, 50.0, n_samples)
    threat_intel_score = np.random.uniform(30.0, 100.0, n_samples)
    threat_severity = np.random.randint(1, 5, n_samples)
    
    control_eff = np.random.uniform(40.0, 99.0, n_samples)
    control_cov = np.random.uniform(30.0, 100.0, n_samples)
    prevention_cap = np.random.uniform(30.0, 99.0, n_samples)
    detection_cap = np.random.uniform(30.0, 99.0, n_samples)
    
    # Ground truth nonlinear risk formulation
    net_exposure = (cvss_score / 10.0) * (0.5 + 0.5 * is_internet_exposed) * (0.8 + 0.4 * weaponized_exploit) * (1.0 - 0.75 * patch_status)
    control_mitigation = (control_eff / 100.0) * (control_cov / 100.0) * (prevention_cap / 100.0)
    
    breach_prob = np.clip(
        0.05 + 0.65 * net_exposure * (1.0 - 0.85 * control_mitigation) + 0.15 * (threat_intel_score / 100.0),
        0.02, 0.98
    )
    
    base_impact = asset_val * (0.05 + 0.04 * asset_crit + 0.03 * data_sensitivity)
    cyber_risk_loss = breach_prob * base_impact * (1.0 + 0.10 * np.log10(np.maximum(10, num_users)))
    
    noise = np.random.normal(1.0, 0.10, n_samples)
    target_risk_loss = np.maximum(25000.0, cyber_risk_loss * noise)

    df = pd.DataFrame({
        "Asset_Value": asset_val,
        "Asset_Criticality": asset_crit,
        "Internet_Exposed": is_internet_exposed,
        "Num_Users": num_users,
        "Data_Sensitivity": data_sensitivity,
        "CVSS_Score": cvss_score,
        "Exploitability": exploitability,
        "Vuln_Age_Days": vuln_age_days,
        "Weaponized_Exploit": weaponized_exploit,
        "Patch_Status_Score": patch_status,
        "Threat_Frequency": threat_freq,
        "Threat_Intel_Score": threat_intel_score,
        "Threat_Severity": threat_severity,
        "Control_Effectiveness": control_eff,
        "Control_Coverage": control_cov,
        "Prevention_Capability": prevention_cap,
        "Detection_Capability": detection_cap,
        "Breach_Probability": breach_prob,
        "Financial_Risk_Loss": target_risk_loss
    })
    
    return df

class CyberRiskMLEngine:
    def __init__(self, model_type: str = "Random Forest"):
        self.model_type = model_type
        self.feature_names = [
            "Asset_Value", "Asset_Criticality", "Internet_Exposed", "Num_Users", "Data_Sensitivity",
            "CVSS_Score", "Exploitability", "Vuln_Age_Days", "Weaponized_Exploit", "Patch_Status_Score",
            "Threat_Frequency", "Threat_Intel_Score", "Threat_Severity",
            "Control_Effectiveness", "Control_Coverage", "Prevention_Capability", "Detection_Capability"
        ]
        self.model = None
        self.metrics = {}
        self.feature_importances_ = None
        self.train_model()

    def train_model(self):
        data = generate_synthetic_training_data(2500)
        X = data[self.feature_names]
        y = data["Financial_Risk_Loss"]

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        if self.model_type == "XGBoost" and XGBOOST_AVAILABLE:
            self.model = xgb.XGBRegressor(
                n_estimators=150,
                max_depth=5,
                learning_rate=0.08,
                random_state=42
            )
        else:
            self.model = RandomForestRegressor(
                n_estimators=120,
                max_depth=8,
                random_state=42
            )

        self.model.fit(X_train, y_train)
        y_pred = self.model.predict(X_test)

        self.metrics = {
            "R2": r2_score(y_test, y_pred),
            "RMSE": np.sqrt(mean_squared_error(y_test, y_pred)),
            "MAE": mean_absolute_error(y_test, y_pred)
        }

        if hasattr(self.model, "feature_importances_"):
            fi = self.model.feature_importances_
            self.feature_importances_ = pd.DataFrame({
                "Feature": self.feature_names,
                "Importance": fi
            }).sort_values(by="Importance", ascending=False)

    def predict(self, input_dict: Dict[str, Any]) -> Tuple[float, float]:
        input_df = pd.DataFrame([input_dict])[self.feature_names]
        pred_loss = float(np.maximum(0.0, self.model.predict(input_df)[0]))
        
        # Calculate predicted breach probability (0 to 1)
        net_exposure = (input_dict["CVSS_Score"] / 10.0) * (0.5 + 0.5 * input_dict["Internet_Exposed"]) * (1.0 - 0.7 * input_dict["Patch_Status_Score"])
        ctrl_eff = (input_dict["Control_Effectiveness"] / 100.0) * (input_dict["Control_Coverage"] / 100.0)
        prob = np.clip(0.08 + 0.65 * net_exposure * (1.0 - 0.8 * ctrl_eff) + 0.15 * (input_dict["Threat_Intel_Score"] / 100.0), 0.02, 0.98)
        
        return pred_loss, float(prob)

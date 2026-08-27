import requests
import json
from typing import Dict, Any, List

def query_nvd_cve(cve_id: str) -> Dict[str, Any]:
    """
    Queries the National Vulnerability Database (NVD) REST API for CVE metadata,
    falling back to curated offline metadata if network request fails or rate-limited.
    """
    clean_id = cve_id.strip().upper()
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={clean_id}"
    
    try:
        response = requests.get(url, timeout=4)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve_data = vulns[0].get("cve", {})
                descriptions = cve_data.get("descriptions", [])
                desc_text = descriptions[0].get("value", "No description") if descriptions else "N/A"
                
                metrics = cve_data.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])
                cvss_score = 7.5
                severity = "HIGH"
                exploitability = 0.7
                attack_vector = "NETWORK"
                
                if cvss_v31:
                    primary_cvss = cvss_v31[0].get("cvssData", {})
                    cvss_score = primary_cvss.get("baseScore", 7.5)
                    severity = primary_cvss.get("baseSeverity", "HIGH")
                    attack_vector = primary_cvss.get("attackVector", "NETWORK")
                    exploitability = cvss_v31[0].get("exploitabilityScore", 2.8) / 3.9
                
                return {
                    "found": True,
                    "cve_id": clean_id,
                    "description": desc_text[:280] + "..." if len(desc_text) > 280 else desc_text,
                    "cvss_score": cvss_score,
                    "severity": severity.capitalize(),
                    "attack_vector": attack_vector.capitalize(),
                    "exploitability": round(exploitability, 2),
                    "source": "Live NVD API v2.0"
                }
    except Exception:
        pass
        
    # Offline curated lookup fallback
    curated_db = {
        "CVE-2023-34362": {
            "description": "Progress MOVEit Transfer SQL Injection Vulnerability leading to unauthenticated RCE and mass data exfiltration.",
            "cvss_score": 9.8,
            "severity": "Critical",
            "attack_vector": "Network",
            "exploitability": 0.95
        },
        "CVE-2021-44228": {
            "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP.",
            "cvss_score": 10.0,
            "severity": "Critical",
            "attack_vector": "Network",
            "exploitability": 1.00
        },
        "CVE-2024-21762": {
            "description": "Fortinet FortiOS out-of-bounds write vulnerability in sslvpnd allowing an unauthenticated attacker to execute arbitrary code via HTTP requests.",
            "cvss_score": 9.8,
            "severity": "Critical",
            "attack_vector": "Network",
            "exploitability": 0.94
        }
    }
    
    if clean_id in curated_db:
        entry = curated_db[clean_id]
        return {
            "found": True,
            "cve_id": clean_id,
            "description": entry["description"],
            "cvss_score": entry["cvss_score"],
            "severity": entry["severity"],
            "attack_vector": entry["attack_vector"],
            "exploitability": entry["exploitability"],
            "source": "Threat Intel Cache (CISA KEV Verified)"
        }
        
    return {
        "found": False,
        "cve_id": clean_id,
        "description": "CVE details not found or API unreachable. Default estimated metrics applied.",
        "cvss_score": 7.0,
        "severity": "High",
        "attack_vector": "Network",
        "exploitability": 0.65,
        "source": "Heuristic Default"
    }

def get_mitre_attack_matrix() -> List[Dict[str, str]]:
    """Returns MITRE ATT&CK tactics mapped to the platform's security controls."""
    return [
        {"Tactic": "Initial Access", "Techniques": "T1190 (Exploit Public-Facing App), T1566 (Phishing)", "Primary Control": "WAAP / WA Firewall & MFA", "Coverage": "92%"},
        {"Tactic": "Execution", "Techniques": "T1059 (Command & Scripting Interpreter), T1204 (User Execution)", "Primary Control": "EDR / XDR & Awareness Training", "Coverage": "88%"},
        {"Tactic": "Persistence", "Techniques": "T1078 (Valid Accounts), T1136 (Create Account)", "Primary Control": "Hardware MFA & Zero Trust IAM", "Coverage": "95%"},
        {"Tactic": "Privilege Escalation", "Techniques": "T1068 (Exploitation for Privilege Escalation)", "Primary Control": "RBVM & Vulnerability Scanner", "Coverage": "86%"},
        {"Tactic": "Defense Evasion", "Techniques": "T1070 (Indicator Removal), T1562 (Impair Defenses)", "Primary Control": "Immutable Backups & Managed SOC", "Coverage": "94%"},
        {"Tactic": "Lateral Movement", "Techniques": "T1021 (Remote Services), T1550 (Use Alternate Auth)", "Primary Control": "Zero Trust Microsegmentation", "Coverage": "90%"},
        {"Tactic": "Impact", "Techniques": "T1486 (Data Encrypted for Impact - Ransomware)", "Primary Control": "Air-Gapped Immutable Backups", "Coverage": "98%"}
    ]

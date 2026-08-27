import pandas as pd

def get_initial_assets_df() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "Asset ID": "AST-101",
            "Asset Name": "Primary Core Banking Database",
            "Asset Type": "Database",
            "Asset Value ($)": 4500000,
            "Asset Criticality": 5,
            "Business Importance": "Mission Critical",
            "Internet Exposure": "No (Internal VPC)",
            "Data Sensitivity": "PCI / Highly Confidential",
            "Number of Users": 150000,
            "Location": "AWS us-east-1",
            "System Availability Requirement": "99.999%"
        },
        {
            "Asset ID": "AST-102",
            "Asset Name": "Public Web Application & API Gateway",
            "Asset Type": "Web Application",
            "Asset Value ($)": 2800000,
            "Asset Criticality": 5,
            "Business Importance": "High",
            "Internet Exposure": "Yes (Public)",
            "Data Sensitivity": "PII & Authentication Tokens",
            "Number of Users": 500000,
            "Location": "Cloudflare / AWS Edge",
            "System Availability Requirement": "99.99%"
        },
        {
            "Asset ID": "AST-103",
            "Asset Name": "Internal Active Directory & IAM Server",
            "Asset Type": "Identity Provider",
            "Asset Value ($)": 3200000,
            "Asset Criticality": 5,
            "Business Importance": "Mission Critical",
            "Internet Exposure": "No (Corporate LAN)",
            "Data Sensitivity": "Credentials / Admin Hashes",
            "Number of Users": 3500,
            "Location": "On-Premises Data Center",
            "System Availability Requirement": "99.999%"
        },
        {
            "Asset ID": "AST-104",
            "Asset Name": "Customer Support CRM Portal (SaaS)",
            "Asset Type": "SaaS Platform",
            "Asset Value ($)": 950000,
            "Asset Criticality": 3,
            "Business Importance": "Moderate",
            "Internet Exposure": "Yes (SaaS Public)",
            "Data Sensitivity": "Customer PII",
            "Number of Users": 450,
            "Location": "Salesforce US-West",
            "System Availability Requirement": "99.9%"
        },
        {
            "Asset ID": "AST-105",
            "Asset Name": "Payment Processing Gateway",
            "Asset Type": "Payment Engine",
            "Asset Value ($)": 6000000,
            "Asset Criticality": 5,
            "Business Importance": "Mission Critical",
            "Internet Exposure": "Yes (Restricted mTLS)",
            "Data Sensitivity": "Cardholder Data (CHD)",
            "Number of Users": 80000,
            "Location": "AWS eu-central-1",
            "System Availability Requirement": "99.999%"
        },
        {
            "Asset ID": "AST-106",
            "Asset Name": "Employee Laptops & Workstations Fleet",
            "Asset Type": "Endpoint Fleet",
            "Asset Value ($)": 1200000,
            "Asset Criticality": 3,
            "Business Importance": "Operational",
            "Internet Exposure": "Yes (Remote Work)",
            "Data Sensitivity": "Internal Proprietary",
            "Number of Users": 3500,
            "Location": "Global Distributed",
            "System Availability Requirement": "99.5%"
        },
        {
            "Asset ID": "AST-107",
            "Asset Name": "Data Lake & Analytics Cluster",
            "Asset Type": "Data Storage",
            "Asset Value ($)": 2100000,
            "Asset Criticality": 4,
            "Business Importance": "High",
            "Internet Exposure": "No (Private Subnet)",
            "Data Sensitivity": "Aggregated Business Intel",
            "Number of Users": 200,
            "Location": "GCP us-central1",
            "System Availability Requirement": "99.9%"
        },
        {
            "Asset ID": "AST-108",
            "Asset Name": "SCADA / Industrial Automation Switch",
            "Asset Type": "OT / SCADA",
            "Asset Value ($)": 3800000,
            "Asset Criticality": 5,
            "Business Importance": "Life Safety / Critical",
            "Internet Exposure": "No (Air-gapped Zone)",
            "Data Sensitivity": "Telemetry & Controls",
            "Number of Users": 45,
            "Location": "Factory Floor - Texas",
            "System Availability Requirement": "99.999%"
        }
    ])

def get_initial_vulnerabilities_df() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "CVE ID": "CVE-2023-34362",
            "Vulnerability Name": "MOVEit Transfer SQL Injection RCE",
            "CVSS Score": 9.8,
            "Vulnerability Severity": "Critical",
            "Exploitability": 0.95,
            "Vulnerability Age (Days)": 240,
            "Patch Status": "Unpatched",
            "Public Exploit Availability": "Weaponized (In-The-Wild)",
            "Affected Asset": "AST-102",
            "Attack Vector": "Network",
            "Attack Complexity": "Low"
        },
        {
            "CVE ID": "CVE-2021-44228",
            "Vulnerability Name": "Log4j Remote Code Execution (Log4Shell)",
            "CVSS Score": 10.0,
            "Vulnerability Severity": "Critical",
            "Exploitability": 1.00,
            "Vulnerability Age (Days)": 800,
            "Patch Status": "Patched",
            "Public Exploit Availability": "Weaponized (In-The-Wild)",
            "Affected Asset": "AST-107",
            "Attack Vector": "Network",
            "Attack Complexity": "Low"
        },
        {
            "CVE ID": "CVE-2023-4966",
            "Vulnerability Name": "Citrix Bleed Sensitive Info Disclosure",
            "CVSS Score": 9.4,
            "Vulnerability Severity": "Critical",
            "Exploitability": 0.90,
            "Vulnerability Age (Days)": 120,
            "Patch Status": "In-Progress",
            "Public Exploit Availability": "Weaponized (In-The-Wild)",
            "Affected Asset": "AST-103",
            "Attack Vector": "Network",
            "Attack Complexity": "Low"
        },
        {
            "CVE ID": "CVE-2023-23397",
            "Vulnerability Name": "Microsoft Outlook NTLM Hash Theft",
            "CVSS Score": 9.8,
            "Vulnerability Severity": "Critical",
            "Exploitability": 0.88,
            "Vulnerability Age (Days)": 310,
            "Patch Status": "Patched",
            "Public Exploit Availability": "Public PoC Available",
            "Affected Asset": "AST-106",
            "Attack Vector": "Network",
            "Attack Complexity": "Low"
        },
        {
            "CVE ID": "CVE-2024-21762",
            "Vulnerability Name": "FortiOS SSL-VPN Out-of-Bounds Write RCE",
            "CVSS Score": 9.8,
            "Vulnerability Severity": "Critical",
            "Exploitability": 0.94,
            "Vulnerability Age (Days)": 45,
            "Patch Status": "Unpatched",
            "Public Exploit Availability": "Weaponized (In-The-Wild)",
            "Affected Asset": "AST-102",
            "Attack Vector": "Network",
            "Attack Complexity": "Low"
        },
        {
            "CVE ID": "CVE-2023-22515",
            "Vulnerability Name": "Confluence Server Broken Access Control",
            "CVSS Score": 9.8,
            "Vulnerability Severity": "Critical",
            "Exploitability": 0.92,
            "Vulnerability Age (Days)": 150,
            "Patch Status": "In-Progress",
            "Public Exploit Availability": "Public PoC Available",
            "Affected Asset": "AST-104",
            "Attack Vector": "Network",
            "Attack Complexity": "Low"
        },
        {
            "CVE ID": "CVE-2022-26134",
            "Vulnerability Name": "Confluence OGNL Injection",
            "CVSS Score": 7.5,
            "Vulnerability Severity": "High",
            "Exploitability": 0.70,
            "Vulnerability Age (Days)": 500,
            "Patch Status": "Patched",
            "Public Exploit Availability": "Public PoC Available",
            "Affected Asset": "AST-104",
            "Attack Vector": "Network",
            "Attack Complexity": "Medium"
        },
        {
            "CVE ID": "CVE-2023-38545",
            "Vulnerability Name": "cURL SOCKS5 Heap Buffer Overflow",
            "CVSS Score": 7.5,
            "Vulnerability Severity": "High",
            "Exploitability": 0.65,
            "Vulnerability Age (Days)": 180,
            "Patch Status": "Patched",
            "Public Exploit Availability": "Proof of Concept",
            "Affected Asset": "AST-105",
            "Attack Vector": "Network",
            "Attack Complexity": "High"
        }
    ])

def get_initial_threats_df() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "Threat ID": "THR-01",
            "Threat Type": "Ransomware & Extortion",
            "Threat Frequency (Events/Yr)": 4.2,
            "Threat Severity": "Critical",
            "Attack Vector": "Phishing / Exposed VPN / Lateral Move",
            "Threat Actor": "Organized Cybercrime (LockBit / BlackCat)",
            "Historical Attack Count": 14,
            "Exploit Availability": "Weaponized Tools",
            "Threat Intelligence Score": 94,
            "Probability of Attack": 0.78
        },
        {
            "Threat ID": "THR-02",
            "Threat Type": "Spear Phishing & Credential Harvesting",
            "Threat Frequency (Events/Yr)": 28.5,
            "Threat Severity": "High",
            "Attack Vector": "Email / Social Engineering / OAuth",
            "Threat Actor": "State-Sponsored / Initial Access Brokers",
            "Historical Attack Count": 142,
            "Exploit Availability": "Automated Kits",
            "Threat Intelligence Score": 88,
            "Probability of Attack": 0.92
        },
        {
            "Threat ID": "THR-03",
            "Threat Type": "DDoS (Distributed Denial of Service)",
            "Threat Frequency (Events/Yr)": 12.0,
            "Threat Severity": "Medium",
            "Attack Vector": "HTTP Flood / UDP Amplification / Botnets",
            "Threat Actor": "Hacktivists / Extortion Gangs",
            "Historical Attack Count": 58,
            "Exploit Availability": "DDoS-as-a-Service",
            "Threat Intelligence Score": 72,
            "Probability of Attack": 0.65
        },
        {
            "Threat ID": "THR-04",
            "Threat Type": "Malware & Infostealers",
            "Threat Frequency (Events/Yr)": 18.0,
            "Threat Severity": "High",
            "Attack Vector": "Drive-by Download / Malvertising",
            "Threat Actor": "RedLine / Lumma Stealer Operators",
            "Historical Attack Count": 89,
            "Exploit Availability": "Dark Web SaaS",
            "Threat Intelligence Score": 84,
            "Probability of Attack": 0.81
        },
        {
            "Threat ID": "THR-05",
            "Threat Type": "Credential Theft & Kerberoasting",
            "Threat Frequency (Events/Yr)": 6.5,
            "Threat Severity": "High",
            "Attack Vector": "Internal Recon / Pass-the-Hash / Mimikatz",
            "Threat Actor": "Advanced Persistent Threats (APTs)",
            "Historical Attack Count": 22,
            "Exploit Availability": "Open Source Tools",
            "Threat Intelligence Score": 86,
            "Probability of Attack": 0.58
        },
        {
            "Threat ID": "THR-06",
            "Threat Type": "Insider Threat (Malicious / Negligent)",
            "Threat Frequency (Events/Yr)": 2.1,
            "Threat Severity": "High",
            "Attack Vector": "Authorized Access / Data Exfiltration",
            "Threat Actor": "Disgruntled Employees / Contractor",
            "Historical Attack Count": 7,
            "Exploit Availability": "Native Enterprise Tools",
            "Threat Intelligence Score": 60,
            "Probability of Attack": 0.35
        },
        {
            "Threat ID": "THR-07",
            "Threat Type": "Web Application & API Attacks (OWASP Top 10)",
            "Threat Frequency (Events/Yr)": 45.0,
            "Threat Severity": "High",
            "Attack Vector": "SQLi / SSRF / Broken Object Auth",
            "Threat Actor": "Opportunistic Scanners & Bug Hunters",
            "Historical Attack Count": 310,
            "Exploit Availability": "Automated Scanners & Exploits",
            "Threat Intelligence Score": 90,
            "Probability of Attack": 0.95
        }
    ])

def get_initial_controls_df() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "Control ID": "SEC-01",
            "Control Name": "Hardware-Backed Multi-Factor Auth (FIDO2/MFA)",
            "Control Cost ($)": 45000,
            "Control Effectiveness (%)": 92,
            "Coverage Percentage (%)": 85,
            "Implementation Status": "Active",
            "Maintenance Cost ($)": 8000,
            "Risk Reduction ($)": 680000,
            "Detection Capability (%)": 60,
            "Prevention Capability (%)": 95,
            "Target Threat": "Spear Phishing / Credential Theft"
        },
        {
            "Control ID": "SEC-02",
            "Control Name": "Next-Gen Web App Firewall & API Protection (WAAP)",
            "Control Cost ($)": 75000,
            "Control Effectiveness (%)": 88,
            "Coverage Percentage (%)": 90,
            "Implementation Status": "Active",
            "Maintenance Cost ($)": 15000,
            "Risk Reduction ($)": 850000,
            "Detection Capability (%)": 85,
            "Prevention Capability (%)": 90,
            "Target Threat": "Web Application & API Attacks / DDoS"
        },
        {
            "Control ID": "SEC-03",
            "Control Name": "Endpoint Detection & Response (EDR / XDR)",
            "Control Cost ($)": 110000,
            "Control Effectiveness (%)": 90,
            "Coverage Percentage (%)": 95,
            "Implementation Status": "Active",
            "Maintenance Cost ($)": 25000,
            "Risk Reduction ($)": 1250000,
            "Detection Capability (%)": 95,
            "Prevention Capability (%)": 88,
            "Target Threat": "Ransomware / Malware / Lateral Move"
        },
        {
            "Control ID": "SEC-04",
            "Control Name": "Next-Gen Network IDS/IPS with Deep Packet Inspection",
            "Control Cost ($)": 60000,
            "Control Effectiveness (%)": 82,
            "Coverage Percentage (%)": 80,
            "Implementation Status": "Planned",
            "Maintenance Cost ($)": 12000,
            "Risk Reduction ($)": 520000,
            "Detection Capability (%)": 90,
            "Prevention Capability (%)": 78,
            "Target Threat": "Exploit Delivery / Network Intrusion"
        },
        {
            "Control ID": "SEC-05",
            "Control Name": "Cloud SIEM & 24/7 Managed SOC Detection",
            "Control Cost ($)": 180000,
            "Control Effectiveness (%)": 94,
            "Coverage Percentage (%)": 95,
            "Implementation Status": "Active",
            "Maintenance Cost ($)": 40000,
            "Risk Reduction ($)": 1400000,
            "Detection Capability (%)": 98,
            "Prevention Capability (%)": 70,
            "Target Threat": "All Complex Threats / Zero-Day / APT"
        },
        {
            "Control ID": "SEC-06",
            "Control Name": "End-to-End Field-Level Encryption & KMS (AES-256)",
            "Control Cost ($)": 65000,
            "Control Effectiveness (%)": 96,
            "Coverage Percentage (%)": 90,
            "Implementation Status": "Active",
            "Maintenance Cost ($)": 10000,
            "Risk Reduction ($)": 920000,
            "Detection Capability (%)": 40,
            "Prevention Capability (%)": 98,
            "Target Threat": "Data Exfiltration / Insider Threat"
        },
        {
            "Control ID": "SEC-07",
            "Control Name": "Air-Gapped Immutable Backups & Disaster Recovery",
            "Control Cost ($)": 95000,
            "Control Effectiveness (%)": 98,
            "Coverage Percentage (%)": 95,
            "Implementation Status": "Active",
            "Maintenance Cost ($)": 20000,
            "Risk Reduction ($)": 1600000,
            "Detection Capability (%)": 30,
            "Prevention Capability (%)": 99,
            "Target Threat": "Ransomware / Data Destruction"
        },
        {
            "Control ID": "SEC-08",
            "Control Name": "Simulated Phishing & Continuous Security Training",
            "Control Cost ($)": 25000,
            "Control Effectiveness (%)": 75,
            "Coverage Percentage (%)": 100,
            "Implementation Status": "Active",
            "Maintenance Cost ($)": 5000,
            "Risk Reduction ($)": 420000,
            "Detection Capability (%)": 65,
            "Prevention Capability (%)": 72,
            "Target Threat": "Spear Phishing / Social Engineering"
        },
        {
            "Control ID": "SEC-09",
            "Control Name": "Continuous Vulnerability & Attack Surface Scanner (RBVM)",
            "Control Cost ($)": 50000,
            "Control Effectiveness (%)": 86,
            "Coverage Percentage (%)": 95,
            "Implementation Status": "Planned",
            "Maintenance Cost ($)": 9000,
            "Risk Reduction ($)": 610000,
            "Detection Capability (%)": 94,
            "Prevention Capability (%)": 65,
            "Target Threat": "Unpatched CVEs / Asset Discovery"
        },
        {
            "Control ID": "SEC-10",
            "Control Name": "Zero Trust Microsegmentation & Software-Defined Perimeter",
            "Control Cost ($)": 150000,
            "Control Effectiveness (%)": 95,
            "Coverage Percentage (%)": 75,
            "Implementation Status": "Planned",
            "Maintenance Cost ($)": 30000,
            "Risk Reduction ($)": 1450000,
            "Detection Capability (%)": 85,
            "Prevention Capability (%)": 96,
            "Target Threat": "Lateral Movement / Credential Theft"
        }
    ])

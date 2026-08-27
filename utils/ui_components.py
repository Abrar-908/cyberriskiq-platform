# CyberRiskIQ UI Styling & Component Utilities

CUSTOM_CSS = """
<style>
/* Dark Cyberpunk / Modern Executive Risk Intelligence Styling */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

code, pre, .mono {
    font-family: 'JetBrains Mono', monospace;
}

/* Background & Glassmorphic Cards */
.stApp {
    background: radial-gradient(circle at 10% 20%, rgba(15, 23, 42, 1) 0%, rgba(2, 6, 23, 1) 90.2%);
    color: #e2e8f0;
}

/* Main title styling */
.cyber-header {
    background: linear-gradient(135deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    font-weight: 800;
    font-size: 2.2rem;
    letter-spacing: -0.02em;
    margin-bottom: 0.2rem;
}

.cyber-subtitle {
    color: #94a3b8;
    font-size: 1rem;
    font-weight: 400;
    margin-bottom: 1.5rem;
}

/* Metric KPI Cards */
.kpi-card {
    background: rgba(30, 41, 59, 0.7);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 14px;
    padding: 1.25rem 1rem;
    text-align: center;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
    transition: transform 0.2s ease, border-color 0.2s ease;
}

.kpi-card:hover {
    transform: translateY(-3px);
    border-color: rgba(56, 189, 248, 0.4);
}

.kpi-title {
    color: #94a3b8;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
    margin-bottom: 0.35rem;
}

.kpi-value {
    font-size: 1.8rem;
    font-weight: 800;
    margin-bottom: 0.2rem;
    font-family: 'JetBrains Mono', monospace;
}

.kpi-delta {
    font-size: 0.8rem;
    font-weight: 600;
}

/* Status colors */
.val-red { color: #f87171; }
.val-amber { color: #fbbf24; }
.val-green { color: #34d399; }
.val-cyan { color: #38bdf8; }
.val-purple { color: #c084fc; }

/* Custom Badge */
.cyber-badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
}
.badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
.badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
.badge-medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
.badge-low { background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e; }

/* Highlight Container */
.highlight-box {
    background: rgba(15, 23, 42, 0.8);
    border: 1px solid rgba(56, 189, 248, 0.25);
    border-radius: 12px;
    padding: 1.25rem;
    margin: 1rem 0;
}

/* Table header styling */
.stDataFrame {
    border-radius: 10px;
    overflow: hidden;
}
</style>
"""

def render_kpi_card(title: str, value: str, delta: str = "", color_class: str = "val-cyan", subtext: str = ""):
    delta_html = f'<div class="kpi-delta {color_class}">{delta}</div>' if delta else ""
    subtext_html = f'<div style="font-size: 0.72rem; color: #64748b; margin-top: 0.25rem;">{subtext}</div>' if subtext else ""
    return f'<div class="kpi-card"><div class="kpi-title">{title}</div><div class="kpi-value {color_class}">{value}</div>{delta_html}{subtext_html}</div>'

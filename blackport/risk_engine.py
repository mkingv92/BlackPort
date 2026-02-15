# =====================================================================
# File: risk_engine.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

def calculate_risk(vuln_list):
    score = 0

    for vuln in vuln_list:
        if "Backdoor" in vuln:
            score += 10
        else:
            score += 5

    if score >= 15:
        return "CRITICAL"
    elif score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    return "LOW"

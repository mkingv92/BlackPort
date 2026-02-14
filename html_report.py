from datetime import datetime

def generate_html_report(results, target, duration, score, high, medium, low, filename):
    # Determine overall risk level
    if score >= 8:
        overall = "CRITICAL"
        overall_color = "#ff0000"
    elif score >= 6:
        overall = "HIGH"
        overall_color = "#ff4d4d"
    elif score >= 4:
        overall = "MEDIUM"
        overall_color = "#ffcc00"
    else:
        overall = "LOW"
        overall_color = "#4CAF50"
 
    def risk_color(risk):
        return {
            "HIGH": "#ff4d4d",
            "MEDIUM": "#ffcc00",
            "LOW": "#4CAF50"
        }.get(risk, "#cccccc")

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Scan Report - {target}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #111;
            color: #eee;
            margin: 40px;
        }}
        h1, h2 {{
            color: #4CAF50;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            border: 1px solid #333;
            padding: 10px;
            text-align: left;
        }}
        th {{
            background-color: #222;
        }}
        .badge {{
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
        }}
        .section {{
            margin-top: 40px;
        }}
    </style>
</head>
<body>

<h1>FastScan Security Report</h1>

<h2 style="color:{overall_color};">
Overall Risk: {overall}
</h2>

<div class="section">
<h2>Executive Summary</h2>
<p><strong>Target:</strong> {target}</p>
<p><strong>Scan Duration:</strong> {duration} seconds</p>
<div style="margin-top:10px;">
    <strong>Exposure Score:</strong> {score}/10
    <div style="
        background:#333;
        border-radius:10px;
        overflow:hidden;
        margin-top:8px;
        height:20px;
        width:400px;">
        <div style="
            height:100%;
            width:{score*10}%;
            background:
                {'#ff4d4d' if score >= 7 else '#ffcc00' if score >=4 else '#4CAF50'};
            transition: width 0.5s;">
        </div>
    </div>
</div>
<p>
<strong>High:</strong> {high} |
<strong>Medium:</strong> {medium} |
<strong>Low:</strong> {low}
</p>
</div>

<div class="section">
<h2>Open Ports</h2>
<table>
<tr>
<th>Port</th>
<th>Service</th>
<th>Product</th>
<th>Version</th>
<th>Risk</th>
<th>Exploit Indicator</th>
</tr>
"""

    for r in results:
        exploit = ""
        if r.get("exploit_indicator"):
            e = r["exploit_indicator"]
            exploit = f"{e['severity']} - {e['description']} ({e['reference']})"

        html_content += f"""
<tr>
<td>{r['port']}</td>
<td>{r['service']}</td>
<td>{r.get('product') or ''}</td>
<td>{r.get('version') or ''}</td>
<td><span class="badge" style="background:{risk_color(r['risk'])};">{r['risk']}</span></td>
<td>{exploit}</td>
</tr>
"""
    remediation = []

    for port in results:
        if port["port"] == 23:
            remediation.append("Disable Telnet service immediately. Use SSH instead.")
        if port["port"] == 21 and port.get("product") == "vsFTPd":
            remediation.append("Patch or remove vulnerable vsFTPd 2.3.4 service.")
        if port["port"] == 80:
            remediation.append("Upgrade Apache to latest supported version.")
        if port["port"] == 22:
            remediation.append("Harden SSH configuration and disable root login.")


    html_content += f"""
</table>
<h2>Recommended Remediation</h2>
<ul>
{''.join(f"<li>{item}</li>" for item in remediation)}
</ul>
</div>

</body>
</html>
"""

    with open(filename, "w") as f:
        f.write(html_content)

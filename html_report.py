# =====================================================================
# File: html_report.py
# Notes:
# - This file is part of the BlackPort project.
# - Professional HTML report with executive summary, severity charts,
#   per-finding CVE details, and remediation guidance.
# - Self-contained single-file HTML — no external dependencies.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from datetime import datetime
import html as html_escape_module


def _e(s):
    """HTML-escape a string safely."""
    return html_escape_module.escape(str(s)) if s is not None else ""


def _risk_color(risk):
    return {
        "CRITICAL": "#e74c3c",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f1c40f",
        "LOW":      "#2ecc71",
    }.get(risk, "#95a5a6")


def _risk_bg(risk):
    return {
        "CRITICAL": "rgba(231,76,60,0.15)",
        "HIGH":     "rgba(230,126,34,0.12)",
        "MEDIUM":   "rgba(241,196,15,0.12)",
        "LOW":      "rgba(46,204,113,0.08)",
    }.get(risk, "rgba(150,150,150,0.08)")


def _remediation_for(r):
    """Generate specific remediation advice per finding."""
    port    = r.get("port")
    service = (r.get("service") or "").upper()
    product = (r.get("product") or "").lower()
    version = (r.get("version") or "")
    risk    = r.get("risk", "LOW")
    tips    = []

    # Per-service remediation
    if port == 21 or service == "FTP":
        if "vsftpd" in product and "2.3.4" in version:
            tips.append("Immediately replace vsFTPd 2.3.4 — contains a known backdoor (CVE-2011-2523).")
        tips.append("Disable FTP if not required. Use SFTP (SSH file transfer) instead.")
        tips.append("If FTP is required: enforce TLS (FTPS), disable anonymous login, restrict to named users.")

    if port == 22 or service == "SSH":
        tips.append("Disable password authentication — use SSH key pairs only.")
        tips.append("Disable root login: set <code>PermitRootLogin no</code> in sshd_config.")
        tips.append("Restrict access by IP using <code>AllowUsers</code> or firewall rules.")
        if version and any(v in version for v in ["4.", "3.", "2."]):
            tips.append(f"Upgrade OpenSSH {version} — end-of-life, multiple unpatched CVEs.")

    if port == 23 or service == "TELNET":
        tips.append("<strong>Disable Telnet immediately</strong> — transmits credentials in cleartext.")
        tips.append("Replace with SSH. If legacy devices require Telnet, isolate on a management VLAN.")

    if port in (80, 8080, 8180) or service == "HTTP":
        tips.append("Enforce HTTPS — redirect all HTTP traffic to port 443.")
        tips.append("Add security headers: HSTS, X-Frame-Options, CSP, X-Content-Type-Options.")
        if "apache 2.2" in f"{product} {version}".lower():
            tips.append("Upgrade Apache 2.2.x — end-of-life since 2017, no security patches.")

    if port in (443, 8443) or service == "HTTPS":
        tips.append("Verify TLS 1.2+ is enforced. Disable TLS 1.0, TLS 1.1, SSLv3.")
        tips.append("Use strong cipher suites — disable RC4, 3DES, NULL, EXPORT ciphers.")
        tips.append("Ensure certificate is valid, not self-signed, and hostname matches.")

    if port in (139, 445) or service in ("SMB", "NETBIOS"):
        tips.append("<strong>Disable SMBv1 immediately</strong> — vulnerable to EternalBlue (CVE-2017-0144).")
        tips.append("Apply MS17-010 patch if running Windows. Enable SMB signing.")
        tips.append("Block SMB (445/tcp) at the perimeter firewall — never expose externally.")

    if port == 3306 or service == "MYSQL":
        tips.append("Ensure MySQL root account requires a strong password.")
        tips.append("Bind MySQL to localhost only — never expose port 3306 externally.")
        tips.append("Audit user privileges. Remove anonymous and wildcard host accounts.")

    if port == 5432 or service == "POSTGRESQL":
        tips.append("Review pg_hba.conf — restrict host-based authentication to required IPs.")
        tips.append("Enforce strong passwords. Disable trust authentication for network connections.")

    if port == 3389 or service == "RDP":
        tips.append("Enable Network Level Authentication (NLA) for RDP.")
        tips.append("Restrict RDP access by IP using firewall rules — never expose externally.")
        tips.append("Apply patches for BlueKeep (CVE-2019-0708) and DejaBlue (CVE-2019-1182).")

    if port == 25 or service == "SMTP":
        tips.append("Disable VRFY and EXPN commands to prevent user enumeration.")
        tips.append("Ensure open relay is disabled — test with: <code>RCPT TO: external@example.com</code>.")
        tips.append("Implement SPF, DKIM, and DMARC records.")

    if port in (8009,) or service == "AJP":
        tips.append("Disable AJP connector in server.xml if not required — vulnerable to Ghostcat (CVE-2020-1938).")
        tips.append("If AJP is required, upgrade Tomcat to 9.0.31+/8.5.51+/7.0.100+ and set secret attribute.")

    if port == 2049 or service == "NFS":
        tips.append("Never export / (root filesystem) to * (everyone) — grants full read access.")
        tips.append("Restrict NFS exports to specific IP addresses in /etc/exports.")
        tips.append("Use NFSv4 with Kerberos authentication where possible.")

    if port == 5900 or service == "VNC":
        tips.append("Use strong VNC passwords (8+ characters, mixed case/numbers/symbols).")
        tips.append("Tunnel VNC over SSH — never expose port 5900 directly.")
        tips.append("Consider replacing VNC with a more secure remote desktop solution.")

    if port == 6667 or service == "IRC":
        tips.append("Verify IRC server version — UnrealIRCd 3.2.8.1 contains a backdoor (CVE-2010-2075).")
        tips.append("If IRC is not required, disable the service entirely.")

    if port == 1099 or service in ("JAVA-RMI", "RMI"):
        tips.append("Disable Java RMI registry if not required — allows remote class loading.")
        tips.append("If required, enforce security manager and restrict codebase URLs.")

    if port == 1524 or service in ("INGRESLOCK", "BINDSHELL"):
        tips.append("<strong>Backdoor detected</strong> — immediately terminate this process and audit the system.")
        tips.append("Perform full forensic investigation — system may be compromised.")

    if port == 3632 or service == "DISTCCD":
        tips.append("Disable distccd if not required — allows unauthenticated RCE (CVE-2004-2687).")
        tips.append("If required, restrict distccd to trusted hosts using --allow flag.")

    if port == 8787 or service == "DRB":
        tips.append("Disable Ruby DRb service if not required — allows unauthenticated RCE.")
        tips.append("If required, add ACL: DRb::DRbServer.default_acl(ACL.new(['deny','all','allow','127.0.0.1'])).")

    # Generic fallbacks by risk level
    if not tips:
        if risk == "CRITICAL":
            tips.append("Immediately assess this finding — CRITICAL severity indicates potential for full system compromise.")
            tips.append("Patch or disable the vulnerable service before the next business day.")
        elif risk == "HIGH":
            tips.append("Remediate within 7 days. Restrict network access to this service while patching.")
        elif risk == "MEDIUM":
            tips.append("Remediate within 30 days. Review service configuration and apply available patches.")
        else:
            tips.append("Review service configuration and ensure only necessary services are exposed.")

    return tips


def generate_html_report(results, target, duration, score, high, medium, low, filename, os_result=None):
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    critical  = len([r for r in results if r.get("risk") == "CRITICAL"])
    total     = len(results)

    # Overall risk
    if critical > 0:
        overall       = "CRITICAL"
        overall_color = "#e74c3c"
    elif high > 0:
        overall       = "HIGH"
        overall_color = "#e67e22"
    elif medium > 0:
        overall       = "MEDIUM"
        overall_color = "#f1c40f"
    else:
        overall       = "LOW"
        overall_color = "#2ecc71"

    # Score bar colour
    score_color = "#e74c3c" if score >= 7 else "#f1c40f" if score >= 4 else "#2ecc71"

    # Build port rows
    port_rows = ""
    for r in results:
        risk         = r.get("risk", "LOW")
        port         = r.get("port", "")
        service      = r.get("service", "")
        product      = r.get("product") or ""
        version      = r.get("version") or ""
        banner       = r.get("banner") or ""
        cve_info     = r.get("cve_info")
        plugins      = r.get("plugins") or []
        exploit_ind  = r.get("exploit_indicator")

        rcolor = _risk_color(risk)
        rbg    = _risk_bg(risk)

        # CVE cell
        cve_cell = ""
        if cve_info:
            cve_cell = f"""
            <div class="cve-block">
                <span class="cve-id">{_e(cve_info.get('cve',''))}</span>
                <span class="cvss-badge">CVSS {cve_info.get('cvss','')}</span>
                <div class="cve-desc">{_e(cve_info.get('description',''))}</div>
                {'<div class="exploit-flag">✓ Exploit Available</div>' if cve_info.get('exploit') else ''}
            </div>"""
        elif exploit_ind:
            cve_cell = f"""
            <div class="cve-block">
                <div class="cve-desc">{_e(exploit_ind.get('description',''))}</div>
                <div class="exploit-flag">Ref: {_e(exploit_ind.get('reference',''))}</div>
            </div>"""

        # Plugin cell
        plugin_cell = ""
        for p in plugins:
            pc     = _risk_color(p.get("risk", "LOW"))
            notes  = _e(p.get("notes", ""))
            # Truncate very long notes for table display
            if len(notes) > 300:
                notes = notes[:300] + "…"
            plugin_cell += f"""
            <div class="plugin-block" style="border-left-color:{pc}">
                <span class="plugin-name">{_e(p.get('plugin',''))}</span>
                <span class="risk-pill" style="background:{pc}">{_e(p.get('risk',''))}</span>
                <div class="plugin-notes">{notes}</div>
                {'<div class="exploit-hint">💡 ' + _e(p.get("exploit_hint","")) + '</div>' if p.get("exploit_hint") else ''}
            </div>"""
        if not plugin_cell:
            plugin_cell = "<span class='none-label'>—</span>"

        # Remediation tips
        tips     = _remediation_for(r)
        rem_html = "".join(f"<li>{t}</li>" for t in tips)

        # Banner (truncated)
        banner_html = ""
        if banner:
            short = _e(banner[:120]) + ("…" if len(banner) > 120 else "")
            banner_html = f'<div class="banner-text">{short}</div>'

        port_rows += f"""
        <tr class="port-row" style="background:{rbg}">
            <td class="port-num">{port}<span class="proto">tcp</span></td>
            <td>
                <strong>{_e(service)}</strong>
                {f'<div class="product">{_e(product)} {_e(version)}</div>' if product else ''}
                {banner_html}
            </td>
            <td><span class="risk-badge" style="background:{rcolor}">{_e(risk)}</span></td>
            <td>{cve_cell}</td>
            <td>{plugin_cell}</td>
            <td><ul class="rem-list">{rem_html}</ul></td>
        </tr>"""

    # Donut chart data
    chart_data   = [critical, high, medium, low]
    chart_colors = ["#e74c3c", "#e67e22", "#f1c40f", "#2ecc71"]
    chart_labels = ["Critical", "High", "Medium", "Low"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BlackPort Report — {_e(target)}</title>
<style>
:root {{
    --bg:       #0d0d0d;
    --surface:  #161616;
    --surface2: #1e1e1e;
    --border:   #2a2a2a;
    --text:     #e8e8e8;
    --muted:    #888;
    --accent:   #00d4aa;
    --critical: #e74c3c;
    --high:     #e67e22;
    --medium:   #f1c40f;
    --low:      #2ecc71;
    --font:     'Segoe UI', system-ui, -apple-system, sans-serif;
    --mono:     'Consolas', 'Monaco', 'Courier New', monospace;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: var(--font);
    background: var(--bg);
    color: var(--text);
    font-size: 14px;
    line-height: 1.6;
}}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
code {{ font-family: var(--mono); background: #222; padding: 1px 5px; border-radius: 3px; font-size: 0.9em; }}

/* Layout */
.wrapper {{ max-width: 1400px; margin: 0 auto; padding: 0 24px 60px; }}

/* Header */
.header {{
    background: linear-gradient(135deg, #0a0a0a 0%, #111827 100%);
    border-bottom: 1px solid var(--border);
    padding: 32px 24px;
    margin-bottom: 32px;
}}
.header-inner {{ max-width: 1400px; margin: 0 auto; display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 20px; }}
.brand {{ display: flex; align-items: center; gap: 12px; }}
.brand-logo {{
    width: 48px; height: 48px;
    background: linear-gradient(135deg, var(--accent), #0097a7);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px; font-weight: 900; color: #000; font-family: var(--mono);
}}
.brand-name {{ font-size: 22px; font-weight: 700; letter-spacing: 1px; color: var(--accent); }}
.brand-sub  {{ font-size: 12px; color: var(--muted); letter-spacing: 2px; text-transform: uppercase; }}
.header-meta {{ text-align: right; }}
.header-meta .target {{ font-size: 24px; font-weight: 700; font-family: var(--mono); color: var(--text); }}
.header-meta .scan-time {{ font-size: 12px; color: var(--muted); margin-top: 4px; }}
.overall-risk {{
    display: inline-block;
    padding: 6px 18px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 13px;
    margin-top: 8px;
    background: {overall_color}22;
    border: 1px solid {overall_color};
    color: {overall_color};
}}

/* Section titles */
.section {{ margin-bottom: 40px; }}
.section-title {{
    font-size: 18px;
    font-weight: 600;
    color: var(--accent);
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 8px;
}}
.section-title::before {{
    content: '';
    display: inline-block;
    width: 4px;
    height: 18px;
    background: var(--accent);
    border-radius: 2px;
}}

/* Summary cards */
.summary-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
}}
.card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    text-align: center;
}}
.card-value {{ font-size: 36px; font-weight: 700; font-family: var(--mono); }}
.card-label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
.card.critical {{ border-color: var(--critical); }}
.card.critical .card-value {{ color: var(--critical); }}
.card.high     {{ border-color: var(--high); }}
.card.high .card-value {{ color: var(--high); }}
.card.medium   {{ border-color: var(--medium); }}
.card.medium .card-value {{ color: var(--medium); }}
.card.low      {{ border-color: var(--low); }}
.card.low .card-value {{ color: var(--low); }}
.card.score    {{ border-color: {score_color}; }}
.card.score .card-value {{ color: {score_color}; }}

/* Score bar */
.score-bar-wrap {{ background: var(--border); border-radius: 6px; height: 8px; margin-top: 10px; overflow: hidden; }}
.score-bar      {{ height: 100%; background: {score_color}; border-radius: 6px; width: {min(score * 10, 100)}%; }}

/* Chart */
.chart-section {{ display: flex; align-items: center; gap: 40px; flex-wrap: wrap; }}
.chart-wrap {{ position: relative; width: 180px; height: 180px; flex-shrink: 0; }}
.chart-center {{
    position: absolute; top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
}}
.chart-center-value {{ font-size: 28px; font-weight: 700; font-family: var(--mono); color: var(--text); }}
.chart-center-label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; }}
.chart-legend {{ display: flex; flex-direction: column; gap: 10px; }}
.legend-item {{ display: flex; align-items: center; gap: 10px; }}
.legend-dot  {{ width: 12px; height: 12px; border-radius: 3px; flex-shrink: 0; }}
.legend-text {{ font-size: 13px; }}
.legend-count {{ font-family: var(--mono); font-weight: 700; margin-left: auto; padding-left: 20px; }}

/* Table */
.table-wrap {{ overflow-x: auto; }}
table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}
thead th {{
    background: var(--surface2);
    padding: 12px 14px;
    text-align: left;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
}}
tbody tr {{
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
}}
tbody tr:hover {{ background: rgba(255,255,255,0.03) !important; }}
td {{ padding: 14px; vertical-align: top; }}

.port-num {{
    font-family: var(--mono);
    font-size: 15px;
    font-weight: 700;
    color: var(--accent);
    white-space: nowrap;
}}
.proto {{ font-size: 10px; color: var(--muted); display: block; }}
.product {{ font-size: 12px; color: var(--muted); margin-top: 3px; }}
.banner-text {{
    font-family: var(--mono);
    font-size: 11px;
    color: #666;
    margin-top: 6px;
    background: var(--surface2);
    padding: 4px 8px;
    border-radius: 4px;
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}}

.risk-badge {{
    display: inline-block;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    color: #fff;
    letter-spacing: 0.5px;
    white-space: nowrap;
}}

.cve-block {{ max-width: 280px; }}
.cve-id {{
    font-family: var(--mono);
    font-size: 12px;
    font-weight: 700;
    color: var(--critical);
}}
.cvss-badge {{
    display: inline-block;
    margin-left: 6px;
    padding: 1px 7px;
    background: #333;
    border-radius: 8px;
    font-size: 11px;
    font-family: var(--mono);
    color: var(--medium);
}}
.cve-desc  {{ font-size: 12px; color: var(--muted); margin-top: 4px; line-height: 1.5; }}
.exploit-flag {{ font-size: 11px; color: var(--critical); margin-top: 4px; font-weight: 600; }}

.plugin-block {{
    border-left: 3px solid #444;
    padding: 6px 10px;
    margin-bottom: 8px;
    background: var(--surface2);
    border-radius: 0 6px 6px 0;
    max-width: 320px;
}}
.plugin-name {{ font-size: 12px; font-weight: 600; }}
.risk-pill {{
    display: inline-block;
    padding: 1px 8px;
    border-radius: 8px;
    font-size: 10px;
    font-weight: 700;
    color: #000;
    margin-left: 6px;
    vertical-align: middle;
}}
.plugin-notes {{ font-size: 11px; color: var(--muted); margin-top: 4px; line-height: 1.5; }}
.exploit-hint {{ font-size: 11px; color: #f39c12; margin-top: 5px; }}
.none-label   {{ color: #444; font-size: 12px; }}

.rem-list {{ padding-left: 16px; max-width: 320px; }}
.rem-list li {{ font-size: 12px; color: var(--muted); margin-bottom: 5px; line-height: 1.5; }}
.rem-list li strong {{ color: var(--text); }}

/* Footer */
.footer {{
    border-top: 1px solid var(--border);
    padding: 24px;
    text-align: center;
    font-size: 12px;
    color: var(--muted);
    margin-top: 40px;
}}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="brand">
      <div class="brand-logo">BP</div>
      <div>
        <div class="brand-name">BLACKPORT</div>
        <div class="brand-sub">Offensive Port Intelligence</div>
      </div>
    </div>
    <div class="header-meta">
      <div class="target">{_e(target)}</div>
      <div class="scan-time">Scan completed {_e(now)} &nbsp;·&nbsp; Duration: {_e(str(duration))}s</div>
      <div><span class="overall-risk">Overall Risk: {_e(overall)}</span></div>
    </div>
  </div>
</div>

<div class="wrapper">

  <!-- Summary cards -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="summary-grid">
      <div class="card">
        <div class="card-value">{total}</div>
        <div class="card-label">Open Ports</div>
      </div>
      <div class="card critical">
        <div class="card-value">{critical}</div>
        <div class="card-label">Critical</div>
      </div>
      <div class="card high">
        <div class="card-value">{high}</div>
        <div class="card-label">High</div>
      </div>
      <div class="card medium">
        <div class="card-value">{medium}</div>
        <div class="card-label">Medium</div>
      </div>
      <div class="card low">
        <div class="card-value">{low}</div>
        <div class="card-label">Low</div>
      </div>
      <div class="card score">
        <div class="card-value">{score}</div>
        <div class="card-label">Exposure Score</div>
        <div class="score-bar-wrap"><div class="score-bar"></div></div>
      </div>
    </div>

    <!-- Donut chart (pure SVG — no JS dependencies) -->
    <div class="chart-section">
      <div class="chart-wrap">
        {_donut_svg(chart_data, chart_colors, total)}
        <div class="chart-center">
          <div class="chart-center-value">{total}</div>
          <div class="chart-center-label">Findings</div>
        </div>
      </div>
      <div class="chart-legend">
        {''.join(f'''
        <div class="legend-item">
          <div class="legend-dot" style="background:{chart_colors[i]}"></div>
          <span class="legend-text">{chart_labels[i]}</span>
          <span class="legend-count" style="color:{chart_colors[i]}">{chart_data[i]}</span>
        </div>''' for i in range(4) if chart_data[i] > 0)}
      </div>
    </div>
  </div>

  <!-- OS detection if available -->
  {_os_section(os_result) if os_result else ''}

  <!-- Port findings table -->
  <div class="section">
    <div class="section-title">Port Findings</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th style="width:80px">Port</th>
            <th style="width:200px">Service</th>
            <th style="width:90px">Risk</th>
            <th style="width:280px">CVE / Vulnerability</th>
            <th style="width:320px">Active Verification</th>
            <th>Remediation</th>
          </tr>
        </thead>
        <tbody>
          {port_rows}
        </tbody>
      </table>
    </div>
  </div>

</div>

<div class="footer">
  BlackPort v2.2.0 &nbsp;·&nbsp; Generated {_e(now)} &nbsp;·&nbsp;
  For authorised security testing only. Handle as confidential.
</div>

</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)


def _donut_svg(data, colors, total):
    """Generate a pure SVG donut chart — zero JS dependencies."""
    if total == 0:
        return '<svg viewBox="0 0 180 180" width="180" height="180"><circle cx="90" cy="90" r="70" fill="none" stroke="#2a2a2a" stroke-width="20"/></svg>'

    cx, cy, r   = 90, 90, 70
    stroke_w    = 22
    circumf     = 2 * 3.14159 * r
    segments    = []
    offset      = 0
    # Start from top (rotate -90deg = offset at -circumf/4)
    dash_offset = circumf / 4

    for i, val in enumerate(data):
        if val <= 0:
            continue
        dash_len = (val / total) * circumf
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="{colors[i]}" stroke-width="{stroke_w}" '
            f'stroke-dasharray="{dash_len:.2f} {circumf - dash_len:.2f}" '
            f'stroke-dashoffset="{-(offset - dash_offset):.2f}" '
            f'transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += dash_len

    inner = "\n".join(segments)
    return f'''<svg viewBox="0 0 180 180" width="180" height="180">
        <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#1e1e1e" stroke-width="{stroke_w}"/>
        {inner}
    </svg>'''


def _os_section(os_result):
    if not os_result:
        return ""
    os_name  = _e(os_result.get("os", "Unknown"))
    os_conf  = _e(os_result.get("confidence", ""))
    os_ttl   = os_result.get("ttl")
    os_meth  = _e(", ".join(os_result.get("methods", [])))
    return f"""
  <div class="section">
    <div class="section-title">OS Detection</div>
    <div class="card" style="display:inline-block; text-align:left; padding: 16px 24px; min-width: 300px;">
      <div style="font-size:18px; font-weight:700; color:var(--accent)">{os_name}</div>
      <div style="color:var(--muted); font-size:12px; margin-top:6px;">
        Confidence: {os_conf}
        {f'&nbsp;·&nbsp; TTL: {os_ttl}' if os_ttl else ''}
        {f'&nbsp;·&nbsp; via {os_meth}' if os_meth else ''}
      </div>
    </div>
  </div>"""

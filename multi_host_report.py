# =====================================================================
# File: multi_host_report.py
# Notes:
# - This file is part of the BlackPort project.
# - Generates a combined HTML report for CIDR/multi-target scans.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from datetime import datetime


def generate_multi_host_report(scan_results_list, filename):
    """
    Generate a combined HTML report for multiple hosts.

    Args:
        scan_results_list: List of scan_data dicts, one per host.
                           Each has keys: target, results, timestamp
        filename:          Output HTML file path
    """

    # --- Aggregate stats ---
    total_hosts   = len(scan_results_list)
    total_ports   = sum(len(s.get("results", [])) for s in scan_results_list)
    total_critical = sum(
        sum(1 for r in s.get("results", []) if r.get("risk") == "CRITICAL")
        for s in scan_results_list
    )
    total_high    = sum(
        sum(1 for r in s.get("results", []) if r.get("risk") == "HIGH")
        for s in scan_results_list
    )

    # Sort hosts by criticality (most dangerous first)
    def host_score(s):
        results = s.get("results", [])
        c = sum(1 for r in results if r.get("risk") == "CRITICAL")
        h = sum(1 for r in results if r.get("risk") == "HIGH")
        return c * 3 + h * 2

    sorted_hosts = sorted(scan_results_list, key=host_score, reverse=True)

    # --- Host summary cards ---
    host_cards_html = ""
    for scan in sorted_hosts:
        target  = scan.get("target", "unknown")
        results = scan.get("results", [])
        os_info = scan.get("os_detection", {})

        c = sum(1 for r in results if r.get("risk") == "CRITICAL")
        h = sum(1 for r in results if r.get("risk") == "HIGH")
        m = sum(1 for r in results if r.get("risk") == "MEDIUM")
        l = sum(1 for r in results if r.get("risk") == "LOW")
        n = len(results)

        score = min(round((c * 3 + h * 2 + m) / max(n, 1) * 10, 1), 10) if n else 0

        if c > 0:
            card_class = "host-critical"
            badge      = "CRITICAL"
        elif h > 0:
            card_class = "host-high"
            badge      = "HIGH"
        elif m > 0:
            card_class = "host-medium"
            badge      = "MEDIUM"
        else:
            card_class = "host-low"
            badge      = "LOW"

        os_str = ""
        if os_info and os_info.get("os_detail"):
            os_str = f'<div class="host-os">🖥 {os_info["os_detail"]}</div>'

        # Critical findings list
        critical_findings = [
            r for r in results if r.get("risk") in ("CRITICAL", "HIGH")
        ]
        findings_html = ""
        for r in critical_findings[:4]:
            risk  = r.get("risk", "LOW")
            color = "#ff2d55" if risk == "CRITICAL" else "#ff6b2d"
            findings_html += (
                f'<div class="host-finding" style="border-left-color:{color}">'
                f'{r.get("port")}/tcp {r.get("service","Unknown")}'
                f'</div>'
            )
        if len(critical_findings) > 4:
            findings_html += f'<div class="host-finding-more">+{len(critical_findings)-4} more</div>'

        host_cards_html += f"""
        <div class="host-card {card_class}">
            <div class="host-header">
                <span class="host-ip">{target}</span>
                <span class="host-badge {badge}">{badge}</span>
            </div>
            {os_str}
            <div class="host-stats">
                <span class="hs-c">{c} CRIT</span>
                <span class="hs-h">{h} HIGH</span>
                <span class="hs-m">{m} MED</span>
                <span class="hs-l">{l} LOW</span>
                <span class="hs-score">Score: {score}/10</span>
            </div>
            <div class="host-findings">{findings_html}</div>
            <div class="host-ports">{n} open port{'s' if n != 1 else ''}</div>
        </div>"""

    # --- Detailed per-host tables ---
    detail_sections_html = ""
    for scan in sorted_hosts:
        target  = scan.get("target", "unknown")
        results = scan.get("results", [])
        os_info = scan.get("os_detection", {})

        c = sum(1 for r in results if r.get("risk") == "CRITICAL")
        h = sum(1 for r in results if r.get("risk") == "HIGH")
        m = sum(1 for r in results if r.get("risk") == "MEDIUM")
        l = sum(1 for r in results if r.get("risk") == "LOW")

        os_line = ""
        if os_info and os_info.get("os_detail"):
            conf = os_info.get("confidence", "LOW")
            ttl  = os_info.get("ttl", "")
            ttl_str = f" · TTL {ttl}" if ttl else ""
            os_line = f'<div class="detail-os">🖥 {os_info["os_detail"]}{ttl_str} <span class="os-conf">[{conf}]</span></div>'

        rows_html = ""
        for r in results:
            risk    = r.get("risk", "LOW")
            port    = r.get("port", "?")
            service = r.get("service", "Unknown")
            product = r.get("product", "")
            version = r.get("version", "")
            banner  = (r.get("banner") or "")[:120]
            plugins = r.get("plugins", [])

            prod_ver = f"{product} {version}".strip() if product else "—"

            risk_colors = {
                "CRITICAL": "#ff2d55", "HIGH": "#ff6b2d",
                "MEDIUM": "#ffd60a",   "LOW":  "#30d158",
            }
            rc = risk_colors.get(risk, "#888")

            plugin_notes = ""
            for p in plugins:
                if not p:
                    continue
                pnotes = (p.get("notes") or "")
                phint  = p.get("exploit_hint", "")
                plugin_notes += f'<div class="dp-plugin"><span class="dp-pname">{p.get("plugin","")}</span> <span class="dp-prisk dp-{p.get("risk","LOW").lower()}">[{p.get("risk","")}]</span><br><span class="dp-notes">{pnotes[:200]}</span>'
                if phint:
                    plugin_notes += f'<div class="dp-hint">💡 {phint}</div>'
                plugin_notes += "</div>"

            rows_html += f"""
            <tr style="border-left:3px solid {rc}">
                <td style="font-family:monospace">{port}/tcp</td>
                <td>{service}</td>
                <td style="font-family:monospace;font-size:0.8rem">{prod_ver}</td>
                <td><span class="dbadge" style="background:{rc}20;color:{rc};border:1px solid {rc}40">{risk}</span></td>
                <td style="font-family:monospace;font-size:0.72rem;color:#888">{banner}</td>
                <td>{plugin_notes if plugin_notes else "<span style='color:#444'>—</span>"}</td>
            </tr>"""

        detail_sections_html += f"""
        <div class="detail-section">
            <div class="detail-host-header">
                <span class="detail-ip">{target}</span>
                <span class="detail-counts">
                    <span style="color:#ff2d55">{c}C</span>
                    <span style="color:#ff6b2d">{h}H</span>
                    <span style="color:#ffd60a">{m}M</span>
                    <span style="color:#30d158">{l}L</span>
                </span>
            </div>
            {os_line}
            <table class="detail-table">
                <thead>
                    <tr>
                        <th>Port</th><th>Service</th><th>Product</th>
                        <th>Risk</th><th>Banner</th><th>Intelligence</th>
                    </tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>"""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BlackPort Network Scan — {total_hosts} Hosts</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #080b0f; --surface: #0d1117; --border: #1e2830;
    --cyan: #00d4ff; --red: #ff2d55; --orange: #ff6b2d;
    --yellow: #ffd60a; --green: #30d158; --purple: #bf5af2;
    --text: #e0e8f0; --text-dim: #4a6070; --mono: 'Share Tech Mono', monospace;
    --sans: 'Exo 2', sans-serif;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: var(--sans); font-size: 14px;
    background-image:
      repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,212,255,0.015) 2px, rgba(0,212,255,0.015) 4px),
      linear-gradient(90deg, transparent 39px, rgba(0,212,255,0.03) 39px, rgba(0,212,255,0.03) 40px);
    background-size: 100% 4px, 40px 40px;
  }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 30px 20px; }}

  /* Header */
  .report-header {{
    display: flex; justify-content: space-between; align-items: flex-start;
    margin-bottom: 30px; padding-bottom: 20px;
    border-bottom: 1px solid var(--border);
  }}
  .logo {{ font-family: var(--mono); font-size: 1.8rem; color: var(--cyan);
           text-shadow: 0 0 20px rgba(0,212,255,0.5); }}
  .logo span {{ color: var(--text-dim); font-size: 1rem; }}

  /* Network summary */
  .net-summary {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 12px; margin-bottom: 30px;
  }}
  .ns-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; padding: 14px; text-align: center;
  }}
  .ns-label {{ font-family: var(--mono); font-size: 0.65rem; color: var(--text-dim);
               text-transform: uppercase; letter-spacing: 0.1em; }}
  .ns-value {{ font-family: var(--mono); font-size: 1.6rem; margin-top: 4px; }}
  .ns-card.crit .ns-value {{ color: var(--red); }}
  .ns-card.high .ns-value {{ color: var(--orange); }}

  /* Section headers */
  .section-header {{
    font-family: var(--mono); font-size: 0.7rem; letter-spacing: 0.15em;
    text-transform: uppercase; color: var(--cyan); padding: 8px 0;
    border-bottom: 1px solid var(--border); margin: 24px 0 16px;
  }}

  /* Host cards grid */
  .host-grid {{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 16px; margin-bottom: 30px;
  }}
  .host-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px;
    transition: border-color 0.2s;
  }}
  .host-card:hover {{ border-color: var(--cyan); }}
  .host-card.host-critical {{ border-left: 3px solid var(--red); }}
  .host-card.host-high     {{ border-left: 3px solid var(--orange); }}
  .host-card.host-medium   {{ border-left: 3px solid var(--yellow); }}
  .host-card.host-low      {{ border-left: 3px solid var(--green); }}

  .host-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
  .host-ip {{ font-family: var(--mono); font-size: 1rem; color: var(--cyan); }}
  .host-badge {{
    font-family: var(--mono); font-size: 0.65rem; padding: 2px 8px;
    border-radius: 3px; font-weight: bold;
  }}
  .host-badge.CRITICAL {{ background: rgba(255,45,85,0.2); color: var(--red); border: 1px solid rgba(255,45,85,0.4); }}
  .host-badge.HIGH     {{ background: rgba(255,107,45,0.2); color: var(--orange); border: 1px solid rgba(255,107,45,0.4); }}
  .host-badge.MEDIUM   {{ background: rgba(255,214,10,0.2); color: var(--yellow); border: 1px solid rgba(255,214,10,0.4); }}
  .host-badge.LOW      {{ background: rgba(48,209,88,0.2); color: var(--green); border: 1px solid rgba(48,209,88,0.4); }}

  .host-os {{ font-size: 0.72rem; color: var(--text-dim); margin-bottom: 8px; }}
  .host-stats {{ display: flex; gap: 8px; font-family: var(--mono); font-size: 0.7rem; margin-bottom: 10px; flex-wrap: wrap; }}
  .hs-c {{ color: var(--red); }} .hs-h {{ color: var(--orange); }}
  .hs-m {{ color: var(--yellow); }} .hs-l {{ color: var(--green); }}
  .hs-score {{ color: var(--text-dim); margin-left: auto; }}

  .host-finding {{
    font-family: var(--mono); font-size: 0.68rem; padding: 3px 6px;
    margin-bottom: 3px; border-left: 2px solid var(--red);
    background: rgba(255,45,85,0.05);
  }}
  .host-finding-more {{ font-size: 0.65rem; color: var(--text-dim); padding: 2px 6px; }}
  .host-ports {{ font-size: 0.68rem; color: var(--text-dim); margin-top: 8px;
                 font-family: var(--mono); }}

  /* Detail sections */
  .detail-section {{
    margin-bottom: 30px; border: 1px solid var(--border);
    border-radius: 8px; overflow: hidden;
  }}
  .detail-host-header {{
    display: flex; justify-content: space-between; align-items: center;
    background: rgba(0,212,255,0.05); padding: 12px 16px;
    border-bottom: 1px solid var(--border);
  }}
  .detail-ip {{ font-family: var(--mono); font-size: 1.1rem; color: var(--cyan); }}
  .detail-counts {{ font-family: var(--mono); font-size: 0.8rem; display: flex; gap: 10px; }}
  .detail-os {{ font-family: var(--mono); font-size: 0.72rem; color: var(--text-dim);
                padding: 6px 16px; background: rgba(0,0,0,0.2); }}
  .os-conf {{ color: var(--text-dim); font-size: 0.65rem; }}

  .detail-table {{ width: 100%; border-collapse: collapse; }}
  .detail-table th {{
    font-family: var(--mono); font-size: 0.65rem; text-transform: uppercase;
    letter-spacing: 0.1em; color: var(--text-dim); padding: 8px 12px;
    text-align: left; background: rgba(0,0,0,0.3);
  }}
  .detail-table td {{
    padding: 10px 12px; border-bottom: 1px solid rgba(30,40,48,0.5);
    vertical-align: top; font-size: 0.82rem;
  }}
  .detail-table tr:hover td {{ background: rgba(0,212,255,0.03); }}
  .dbadge {{
    font-family: var(--mono); font-size: 0.65rem; padding: 2px 7px;
    border-radius: 3px; white-space: nowrap;
  }}

  /* Plugin output */
  .dp-plugin {{ margin-bottom: 6px; padding: 6px 8px;
                background: rgba(0,0,0,0.3); border-radius: 4px; font-size: 0.75rem; }}
  .dp-pname {{ color: var(--cyan); font-family: var(--mono); font-size: 0.7rem; }}
  .dp-prisk {{ font-family: var(--mono); font-size: 0.65rem; }}
  .dp-prisk.dp-critical {{ color: var(--red); }}
  .dp-prisk.dp-high {{ color: var(--orange); }}
  .dp-prisk.dp-medium {{ color: var(--yellow); }}
  .dp-prisk.dp-low {{ color: var(--green); }}
  .dp-notes {{ color: #8899aa; font-size: 0.72rem; }}
  .dp-hint {{ font-family: var(--mono); font-size: 0.68rem; color: var(--yellow);
              margin-top: 4px; padding: 3px 6px; background: rgba(255,214,10,0.08);
              border-left: 2px solid var(--yellow); }}

  .ts {{ font-family: var(--mono); font-size: 0.65rem; color: var(--text-dim);
         text-align: center; padding: 20px 0 10px; }}
</style>
</head>
<body>
<div class="container">

<div class="report-header">
  <div>
    <div class="logo">BLACKPORT <span>v2.1.0 // NETWORK SCAN</span></div>
    <div style="font-family:var(--mono);font-size:0.7rem;color:var(--text-dim);margin-top:6px">
      {total_hosts} hosts scanned · {timestamp}
    </div>
  </div>
</div>

<div class="net-summary">
  <div class="ns-card">
    <div class="ns-label">Hosts Scanned</div>
    <div class="ns-value" style="color:var(--cyan)">{total_hosts}</div>
  </div>
  <div class="ns-card">
    <div class="ns-label">Open Ports</div>
    <div class="ns-value" style="color:var(--text)">{total_ports}</div>
  </div>
  <div class="ns-card crit">
    <div class="ns-label">Critical</div>
    <div class="ns-value">{total_critical}</div>
  </div>
  <div class="ns-card high">
    <div class="ns-label">High</div>
    <div class="ns-value">{total_high}</div>
  </div>
</div>

<div class="section-header">Host Overview</div>
<div class="host-grid">
  {host_cards_html}
</div>

<div class="section-header">Detailed Findings</div>
{detail_sections_html}

<div class="ts">Generated by BlackPort v2.1.0 &nbsp;·&nbsp; {timestamp}</div>
</div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

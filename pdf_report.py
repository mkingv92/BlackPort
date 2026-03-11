# =====================================================================
# File: pdf_report.py
# Notes:
# - This file is part of the BlackPort project.
# - Generates a professional PDF report from scan results.
# - Uses reportlab Platypus (flowable layout engine).
# - Self-contained — no external fonts or assets required.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import re
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Wedge, String

# ── Colour palette ────────────────────────────────────────────────────
C_BG       = colors.HexColor("#0d0d0d")
C_SURFACE  = colors.HexColor("#161616")
C_SURFACE2 = colors.HexColor("#1a1a1a")
C_BORDER   = colors.HexColor("#2a2a2a")
C_TEXT     = colors.HexColor("#e8e8e8")
C_MUTED    = colors.HexColor("#888888")
C_ACCENT   = colors.HexColor("#00d4aa")
C_CRITICAL = colors.HexColor("#e74c3c")
C_HIGH     = colors.HexColor("#e67e22")
C_MEDIUM   = colors.HexColor("#f1c40f")
C_LOW      = colors.HexColor("#2ecc71")

PAGE_W, PAGE_H = A4
MARGIN         = 18 * mm

# Column widths — must sum to exactly 174mm (A4 - 2×18mm margins)
COL_PORT    = 14 * mm
COL_SERVICE = 34 * mm
COL_RISK    = 22 * mm   # wide enough for "CRITICAL" at 8pt bold + 10mm padding
COL_CVE     = 40 * mm
COL_VERIFY  = 40 * mm
COL_REM     = 24 * mm
COL_WIDTHS  = [COL_PORT, COL_SERVICE, COL_RISK, COL_CVE, COL_VERIFY, COL_REM]


# ── Helpers ───────────────────────────────────────────────────────────

def _risk_color(risk):
    return {"CRITICAL": C_CRITICAL, "HIGH": C_HIGH,
            "MEDIUM": C_MEDIUM, "LOW": C_LOW}.get(risk, C_MUTED)


def _risk_bg(risk):
    return {"CRITICAL": colors.HexColor("#200808"),
            "HIGH":     colors.HexColor("#1c1008"),
            "MEDIUM":   colors.HexColor("#1c1a06"),
            "LOW":      colors.HexColor("#081508"),
            }.get(risk, colors.HexColor("#141414"))


def _clean_banner(raw):
    """
    Strip non-printable bytes (telnet IAC sequences, escape codes, etc.)
    from a raw banner string and return clean ASCII-printable text.
    Suppresses banners that are pure protocol negotiation noise.
    """
    if not raw:
        return ""
    # Remove ANSI escape sequences
    raw = re.sub(r'\x1b\[[0-9;]*[mABCDEFGHJKLMnsuhl]', '', raw)
    # Keep only printable ASCII (32-126) plus tab/newline
    cleaned = ''.join(c for c in raw if 32 <= ord(c) <= 126 or c in '\t\n')
    # Collapse runs of whitespace/newlines to a single space
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    # Suppress if fewer than 4 alphanumeric chars remain (IAC/negotiation noise)
    if len(re.sub(r'[^a-zA-Z0-9]', '', cleaned)) < 4:
        return ""
    return cleaned


def _trunc(text, max_chars):
    """Truncate at a word boundary, appending ellipsis if needed."""
    if not text or len(text) <= max_chars:
        return text
    cut = text[:max_chars].rsplit(' ', 1)[0]
    return cut.rstrip('.,|—-') + '…'


def _strip_html(text):
    """Remove basic HTML tags for clean PDF text."""
    return re.sub(r'<[^>]+>', '', text)


# ── Remediation (self-contained — no html_report dependency) ─────────

def _remediation_for(r):
    port    = r.get("port")
    service = (r.get("service") or "").upper()
    product = (r.get("product") or "").lower()
    version = (r.get("version") or "")
    risk    = r.get("risk", "LOW")
    tips    = []

    if port == 21 or service == "FTP":
        if "vsftpd" in product and "2.3.4" in version:
            tips.append("Immediately replace vsFTPd 2.3.4 — contains a known backdoor (CVE-2011-2523).")
        tips.append("Disable FTP if not required. Use SFTP (SSH file transfer) instead.")
        tips.append("If FTP is required: enforce TLS (FTPS), disable anonymous login.")

    elif port == 22 or service == "SSH":
        tips.append("Disable password authentication — use SSH key pairs only.")
        tips.append("Set PermitRootLogin no and restrict access by IP via AllowUsers.")
        if version and any(v in version for v in ["4.", "3.", "2."]):
            tips.append(f"Upgrade OpenSSH {version} — end-of-life, multiple unpatched CVEs.")

    elif port == 23 or service == "TELNET":
        tips.append("Disable Telnet immediately — transmits credentials in cleartext.")
        tips.append("Replace with SSH. Isolate legacy Telnet devices on a management VLAN.")

    elif port in (80, 8080, 8180) or service == "HTTP":
        tips.append("Enforce HTTPS — redirect all HTTP traffic to port 443.")
        tips.append("Add security headers: HSTS, X-Frame-Options, CSP.")
        if "apache 2.2" in f"{product} {version}".lower():
            tips.append("Upgrade Apache 2.2.x — end-of-life since 2017, no security patches.")

    elif port in (443, 8443) or service == "HTTPS":
        tips.append("Enforce TLS 1.2+. Disable TLS 1.0, 1.1, SSLv3.")
        tips.append("Use strong cipher suites — disable RC4, 3DES, EXPORT ciphers.")
        tips.append("Ensure certificate is valid, not self-signed, and hostname matches.")

    elif port in (139, 445) or service in ("SMB", "NETBIOS"):
        tips.append("Disable SMBv1 immediately — vulnerable to EternalBlue (CVE-2017-0144).")
        tips.append("Apply MS17-010 patch if running Windows. Enable SMB signing.")
        tips.append("Block SMB (445/tcp) at the perimeter — never expose externally.")

    elif port == 512 or service == "REXEC":
        tips.append("Disable rexec (port 512) — legacy protocol with no encryption or strong auth.")
        tips.append("Remove /etc/hosts.equiv and ~/.rhosts trust files.")
        tips.append("Replace with SSH for all remote execution needs.")

    elif port == 513 or service in ("RLOGIN", "LOGIN"):
        tips.append("Disable rlogin (port 513) — allows unauthenticated login via .rhosts trust.")
        tips.append("Remove /etc/hosts.equiv and all ~/.rhosts files immediately.")
        tips.append("Replace with SSH. Block ports 512-514 at the firewall.")

    elif port == 514 or service == "RSH":
        tips.append("Disable rsh (port 514) — allows unauthenticated command execution via .rhosts.")
        tips.append("Remove /etc/hosts.equiv and all ~/.rhosts files immediately.")
        tips.append("Replace with SSH. Block ports 512-514 at the firewall.")

    elif port == 3306 or service == "MYSQL":
        tips.append("Ensure MySQL root requires a strong password — run mysql_secure_installation.")
        tips.append("Bind MySQL to 127.0.0.1 only. Never expose port 3306 externally.")
        tips.append("Audit user privileges. Remove anonymous and wildcard host accounts.")

    elif port == 5432 or service == "POSTGRESQL":
        tips.append("Review pg_hba.conf — restrict to required IPs only.")
        tips.append("Disable trust authentication for network connections.")

    elif port == 3389 or service == "RDP":
        tips.append("Enable Network Level Authentication (NLA) for RDP.")
        tips.append("Restrict RDP by IP via firewall. Apply BlueKeep patch (CVE-2019-0708).")

    elif port == 25 or service == "SMTP":
        tips.append("Disable VRFY and EXPN commands to prevent user enumeration.")
        tips.append("Ensure open relay is disabled. Implement SPF, DKIM, and DMARC.")

    elif port in (8009,) or service == "AJP":
        tips.append("Disable AJP connector in server.xml — vulnerable to Ghostcat (CVE-2020-1938).")
        tips.append("If AJP is required: upgrade Tomcat and set the secret attribute.")

    elif port == 2049 or service == "NFS":
        tips.append("Never export / to * — restrict NFS exports to specific IPs in /etc/exports.")
        tips.append("Use NFSv4 with Kerberos authentication where possible.")

    elif port == 5900 or service == "VNC":
        tips.append("Use a strong VNC password. Tunnel VNC over SSH — never expose port 5900.")

    elif port == 6667 or service == "IRC":
        tips.append("Verify IRC version — UnrealIRCd 3.2.8.1 contains a backdoor (CVE-2010-2075).")
        tips.append("Disable IRC if not required.")

    elif port == 1099 or service in ("JAVA-RMI", "RMI"):
        tips.append("Disable Java RMI registry if not required — allows remote class loading.")

    elif port == 1524 or service in ("INGRESLOCK", "BINDSHELL"):
        tips.append("Backdoor detected — immediately terminate this process and audit the system.")
        tips.append("Perform full forensic investigation — system is likely compromised.")

    elif port == 3632 or service == "DISTCCD":
        tips.append("Disable distccd — allows unauthenticated RCE (CVE-2004-2687).")
        tips.append("If required, restrict with --allow flag to trusted hosts only.")

    elif port == 53 or service == "DNS":
        tips.append("Disable zone transfers (AXFR) to untrusted IPs.")
        tips.append("Suppress DNS version string via version.bind chaos TXT record.")

    elif port == 111 or service == "RPC":
        tips.append("Block portmapper (111/tcp) at the firewall — exposes RPC service list.")
        tips.append("Disable unused RPC services. Restrict access to management networks only.")

    if not tips:
        if risk == "CRITICAL":
            tips.append("Immediately assess — CRITICAL severity indicates potential full system compromise.")
            tips.append("Patch or disable before the next business day.")
        elif risk == "HIGH":
            tips.append("Remediate within 7 days. Restrict network access while patching.")
        elif risk == "MEDIUM":
            tips.append("Remediate within 30 days. Review service configuration.")
        else:
            tips.append("Review configuration and ensure only necessary services are exposed.")

    return tips


# ── Styles ────────────────────────────────────────────────────────────

def _styles():
    return {
        "h1": ParagraphStyle("h1",
            fontName="Helvetica-Bold", fontSize=22,
            textColor=C_ACCENT, leading=28, spaceAfter=4),
        "h2": ParagraphStyle("h2",
            fontName="Helvetica-Bold", fontSize=14,
            textColor=C_ACCENT, leading=18, spaceBefore=12, spaceAfter=6),
        "muted": ParagraphStyle("muted",
            fontName="Helvetica", fontSize=8,
            textColor=C_MUTED, leading=12),
    }


# ── Donut chart ───────────────────────────────────────────────────────

def _donut_chart(critical, high, medium, low, total, size=90):
    d      = Drawing(size, size)
    d.background = None  # transparent — no white box behind chart
    cx, cy = size / 2, size / 2
    r_out  = size * 0.42
    r_in   = size * 0.26

    data = [critical, high, medium, low]
    cols = [C_CRITICAL, C_HIGH, C_MEDIUM, C_LOW]

    if total == 0:
        from reportlab.graphics.shapes import Ellipse
        ring = Ellipse(cx - r_out, cy - r_out, cx + r_out, cy + r_out)
        ring.fillColor = None; ring.strokeColor = C_BORDER
        ring.strokeWidth = r_out - r_in
        d.add(ring)
    else:
        # ReportLab Wedge draws CCW from startangle to endangle.
        # We want a CW donut starting at the top (90°).
        # For each slice: cw_end = cw_start - sweep.
        # To draw CCW equivalent: pass (cw_end, cw_start) so start < end.
        cw_pos = 90.0
        for val, col in zip(data, cols):
            if val == 0:
                continue
            sweep   = 360.0 * val / total
            cw_end  = cw_pos - sweep
            # Pass (cw_end, cw_pos): CCW from cw_end to cw_pos = correct CW arc
            w = Wedge(cx, cy, r_out, cw_end, cw_pos, radius1=r_in)
            w.fillColor = col; w.strokeColor = C_BG; w.strokeWidth = 1.5
            d.add(w)
            cw_pos  = cw_end

    # Center labels — black text for readability on any background
    d.add(String(cx, cy + 4, str(total),
        fontName="Helvetica-Bold", fontSize=16,
        fillColor=colors.black, textAnchor="middle"))
    d.add(String(cx, cy - 9, "findings",
        fontName="Helvetica", fontSize=7,
        fillColor=colors.HexColor("#333333"), textAnchor="middle"))
    return d


# ── Header/footer ─────────────────────────────────────────────────────

class _DocTemplate(SimpleDocTemplate):
    def __init__(self, filename, target, scan_time, **kwargs):
        self._target    = target
        self._scan_time = scan_time
        self._page_num  = 0
        super().__init__(filename, **kwargs)

    def handle_pageBegin(self):
        self._page_num += 1
        super().handle_pageBegin()

    def afterPage(self):
        c = self.canv
        w = PAGE_W
        # Header
        c.setFillColor(C_SURFACE)
        c.rect(0, PAGE_H - 14*mm, w, 14*mm, fill=1, stroke=0)
        c.setFillColor(C_ACCENT)
        c.rect(0, PAGE_H - 14*mm, 2, 14*mm, fill=1, stroke=0)
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(C_ACCENT)
        c.drawString(MARGIN, PAGE_H - 9*mm, "BLACKPORT")
        c.setFont("Helvetica", 8)
        c.setFillColor(C_MUTED)
        c.drawString(MARGIN + 58, PAGE_H - 9*mm, "Security Report")
        c.drawRightString(w - MARGIN, PAGE_H - 9*mm, self._target)
        # Footer
        c.setFillColor(C_SURFACE)
        c.rect(0, 0, w, 10*mm, fill=1, stroke=0)
        c.setFillColor(C_MUTED)
        c.setFont("Helvetica", 7)
        c.drawString(MARGIN, 6*mm,
            f"Generated {self._scan_time}  ·  For authorised security testing only  ·  Handle as CONFIDENTIAL")
        c.drawRightString(w - MARGIN, 6*mm, f"Page {self._page_num}")


# ── Main entry point ──────────────────────────────────────────────────

def generate_pdf_report(results, target, duration, score, high, medium, low, filename):
    critical  = len([r for r in results if r.get("risk") == "CRITICAL"])
    total     = len(results)
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    S         = _styles()

    if critical > 0:   overall, overall_color = "CRITICAL", C_CRITICAL
    elif high > 0:     overall, overall_color = "HIGH",     C_HIGH
    elif medium > 0:   overall, overall_color = "MEDIUM",   C_MEDIUM
    else:              overall, overall_color = "LOW",       C_LOW

    score_color = C_CRITICAL if score >= 7 else C_MEDIUM if score >= 4 else C_LOW

    doc = _DocTemplate(
        filename, target=target, scan_time=now,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=22*mm, bottomMargin=16*mm,
    )
    story = []

    # ── Cover ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph("Security Assessment Report", S["h1"]))
    story.append(Paragraph(f"Target: {target}", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=8))

    meta_data = [
        ("Target",         target,              None),
        ("Scan Date",      now,                 None),
        ("Duration",       f"{duration}s",      None),
        ("Ports Scanned",  str(total),          None),
        ("Overall Risk",   overall,             overall_color),
        ("Exposure Score", f"{score}/10",       score_color),
        ("Generated By",   "BlackPort v2.2.0",  None),
    ]
    meta_rows = []
    for label, val, col in meta_data:
        lp = Paragraph(label, ParagraphStyle("ml",
            fontName="Helvetica-Bold", fontSize=9, textColor=C_MUTED))
        vp = Paragraph(val, ParagraphStyle("mv",
            fontName="Helvetica-Bold" if col else "Helvetica", fontSize=9,
            textColor=col or C_TEXT))
        meta_rows.append([lp, vp])

    mt = Table(meta_rows, colWidths=[45*mm, 110*mm])
    mt.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_SURFACE, C_SURFACE2]),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING",   (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ("LINEAFTER",    (0,0), (0,-1), 0.5, C_BORDER),
        ("BOX",          (0,0), (-1,-1), 0.5, C_BORDER),
    ]))
    story.append(mt)
    story.append(Spacer(1, 6*mm))

    # ── Executive Summary ─────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))

    card_data = [
        (str(critical), "CRITICAL", C_CRITICAL),
        (str(high),     "HIGH",     C_HIGH),
        (str(medium),   "MEDIUM",   C_MEDIUM),
        (str(low),      "LOW",      C_LOW),
        (str(total),    "TOTAL",    C_ACCENT),
    ]
    cards = Table(
        [[Paragraph(v, ParagraphStyle(f"cv{i}", fontName="Helvetica-Bold",
            fontSize=22, textColor=c, leading=26, alignment=TA_CENTER))
          for i,(v,_,c) in enumerate(card_data)],
         [Paragraph(l, ParagraphStyle(f"cl{i}", fontName="Helvetica-Bold",
            fontSize=7, textColor=c, leading=10, alignment=TA_CENTER))
          for i,(_,l,c) in enumerate(card_data)]],
        colWidths=[30*mm]*5,
    )
    cards.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), C_SURFACE),
        ("ALIGN",        (0,0), (-1,-1), "CENTER"),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",   (0,0), (-1,0),  10),
        ("BOTTOMPADDING",(0,0), (-1,0),  2),
        ("BOTTOMPADDING",(0,1), (-1,1),  8),
        ("BOX",          (0,0), (-1,-1), 0.5, C_BORDER),
        ("LINEBEFORE",   (1,0), (-1,-1), 0.5, C_BORDER),
    ]))

    donut = _donut_chart(critical, high, medium, low, total)
    legend_rows = [[
        Paragraph("■", ParagraphStyle(f"li{i}", fontName="Helvetica-Bold",
            fontSize=9, textColor=c)),
        Paragraph(f"{l}  {v}", ParagraphStyle(f"lt{i}",
            fontName="Helvetica", fontSize=8, textColor=C_TEXT)),
    ] for i,(v,l,c) in enumerate(card_data[:4]) if int(v) > 0]

    legend = Table(legend_rows, colWidths=[6*mm, 32*mm]) if legend_rows else Spacer(1,1)
    if legend_rows:
        legend.setStyle(TableStyle([
            ("LEFTPADDING", (0,0),(-1,-1), 0),
            ("TOPPADDING",  (0,0),(-1,-1), 2),
            ("BOTTOMPADDING",(0,0),(-1,-1), 2),
        ]))

    chart_area = Table([[donut, legend]], colWidths=[36*mm, 40*mm])
    chart_area.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("LEFTPADDING",(0,0),(-1,-1),0),
        ("RIGHTPADDING",(0,0),(-1,-1),0),
        ("TOPPADDING",(0,0),(-1,-1),0),
        ("BOTTOMPADDING",(0,0),(-1,-1),0),
    ]))

    summary = Table([[cards, chart_area]], colWidths=[150*mm, 24*mm])
    summary.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("LEFTPADDING",(0,0),(-1,-1),0),
        ("RIGHTPADDING",(0,0),(-1,-1),0),
        ("TOPPADDING",(0,0),(-1,-1),0),
        ("BOTTOMPADDING",(0,0),(-1,-1),0),
    ]))
    story.append(summary)
    story.append(Spacer(1, 8*mm))

    # ── Findings table ────────────────────────────────────────────────
    story.append(Paragraph("Port Findings", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))

    hdr = ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=8,
                         textColor=C_MUTED, leading=11)
    headers = [
        Paragraph("PORT",                hdr),
        Paragraph("SERVICE",             hdr),
        Paragraph("RISK",                hdr),
        Paragraph("CVE / VULNERABILITY", hdr),
        Paragraph("ACTIVE VERIFICATION", hdr),
        Paragraph("REMEDIATION",         hdr),
    ]
    table_rows = [headers]

    for r in results:
        risk    = r.get("risk", "LOW")
        port    = str(r.get("port", ""))
        service = r.get("service", "")
        product = r.get("product") or ""
        version = r.get("version") or ""
        banner  = _clean_banner(r.get("banner") or "")
        cve     = r.get("cve_info")
        plugins = r.get("plugins") or []
        exploit = r.get("exploit_indicator")
        rc      = _risk_color(risk)

        # Port cell
        port_p = Paragraph(
            f'<font name="Courier-Bold" size="10" color="{rc.hexval()}">{port}</font>'
            f'<font name="Helvetica" size="7" color="#888888"><br/>tcp</font>',
            ParagraphStyle("pp", leading=13))

        # Service cell — clean banner, word-boundary truncate
        svc_parts = [f'<b>{service}</b>']
        if product:
            svc_parts.append(f'<font size="7" color="#888888">{_trunc(f"{product} {version}".strip(), 28)}</font>')
        if banner:
            svc_parts.append(f'<font name="Courier" size="6" color="#444444">{_trunc(banner, 40)}</font>')
        svc_p = Paragraph("<br/>".join(svc_parts),
            ParagraphStyle("sp", fontName="Helvetica", fontSize=9,
                           textColor=C_TEXT, leading=12))

        # Risk cell — coloured text, no wrapping issues at 22mm
        risk_p = Paragraph(risk,
            ParagraphStyle("rp", fontName="Helvetica-Bold", fontSize=8,
                           textColor=rc, leading=12))

        # CVE cell
        cve_parts = []
        if cve:
            cve_parts.append(f'<font name="Courier-Bold" size="8" color="{C_CRITICAL.hexval()}">{cve.get("cve","")}</font>')
            cve_parts.append(f'<font size="7" color="{C_MEDIUM.hexval()}">CVSS {cve.get("cvss","")}</font>')
            desc = _trunc(cve.get("description",""), 110)
            if desc:
                cve_parts.append(f'<font size="7" color="#888888">{desc}</font>')
            if cve.get("exploit"):
                cve_parts.append(f'<font size="7" color="{C_CRITICAL.hexval()}">✓ Exploit Available</font>')
        elif exploit:
            cve_parts.append(f'<font size="7" color="#888888">{_trunc(exploit.get("description",""), 110)}</font>')
        cve_p = Paragraph("<br/>".join(cve_parts) if cve_parts else "—",
            ParagraphStyle("cp", fontName="Helvetica", fontSize=8,
                           textColor=C_TEXT, leading=11))

        # Plugin cell — word-boundary truncated notes
        plugin_parts = []
        for p in plugins[:2]:
            pc    = _risk_color(p.get("risk","LOW"))
            pname = _trunc(p.get("plugin",""), 30)
            notes = _trunc(_strip_html(p.get("notes") or ""), 95)
            hint  = _trunc(p.get("exploit_hint") or "", 60)
            plugin_parts.append(
                f'<font name="Helvetica-Bold" size="8" color="{C_TEXT.hexval()}">{pname}</font>'
                f' <font size="7" color="{pc.hexval()}">[{p.get("risk","")}]</font>'
                + (f'<br/><font size="7" color="#888888">{notes}</font>' if notes else "")
            )
            if hint:
                plugin_parts.append(f'<font size="7" color="{C_MEDIUM.hexval()}">&#9657; {hint}</font>')
        plug_p = Paragraph("<br/>".join(plugin_parts) if plugin_parts else "—",
            ParagraphStyle("plp", fontName="Helvetica", fontSize=8,
                           textColor=C_TEXT, leading=11))

        # Remediation cell — word-boundary truncated
        tips  = _remediation_for(r)
        rem_p = Paragraph(
            "<br/>".join(
                f'<font size="7" color="#aaaaaa">• {_trunc(_strip_html(t), 70)}</font>'
                for t in tips[:3]
            ) or "—",
            ParagraphStyle("rmp", fontName="Helvetica", fontSize=7,
                           textColor=C_MUTED, leading=11))

        table_rows.append([port_p, svc_p, risk_p, cve_p, plug_p, rem_p])

    row_styles = [
        ("BACKGROUND",   (0,0), (-1,0),   colors.HexColor("#1e1e1e")),
        ("LINEBELOW",    (0,0), (-1,0),   0.5, C_ACCENT),
        ("LINEBELOW",    (0,1), (-1,-1),  0.3, C_BORDER),
        ("LEFTPADDING",  (0,0), (-1,-1),  5),
        ("RIGHTPADDING", (0,0), (-1,-1),  5),
        ("TOPPADDING",   (0,0), (-1,-1),  5),
        ("BOTTOMPADDING",(0,0), (-1,-1),  5),
        ("VALIGN",       (0,0), (-1,-1),  "TOP"),
        ("BOX",          (0,0), (-1,-1),  0.5, C_BORDER),
    ]
    for i, r in enumerate(results, start=1):
        row_styles.append(("BACKGROUND", (0,i), (-1,i), _risk_bg(r.get("risk","LOW"))))

    ft = Table(table_rows, colWidths=COL_WIDTHS, repeatRows=1, splitByRow=1)
    ft.setStyle(TableStyle(row_styles))
    story.append(ft)
    story.append(Spacer(1, 8*mm))

    # ── Recommendations ───────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Recommendations", S["h2"]))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))

    for risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        group = [r for r in results if r.get("risk") == risk_level]
        if not group:
            continue

        rc = _risk_color(risk_level)
        story.append(Paragraph(risk_level, ParagraphStyle("rl",
            fontName="Helvetica-Bold", fontSize=10,
            textColor=rc, leading=14, spaceBefore=8, spaceAfter=4)))

        for r in group:
            tips = _remediation_for(r)
            if not tips:
                continue
            port    = r.get("port","")
            service = r.get("service","")
            block   = [Paragraph(
                f'<font name="Courier-Bold" size="9" color="{C_ACCENT.hexval()}">{port}/tcp</font>'
                f'  <font name="Helvetica-Bold" size="9" color="{C_TEXT.hexval()}">{service}</font>',
                ParagraphStyle("rb", leading=14))]
            for tip in tips:
                block.append(Paragraph(
                    f"• {_strip_html(tip)}",
                    ParagraphStyle("rt", fontName="Helvetica", fontSize=8,
                                   textColor=colors.HexColor("#aaaaaa"),
                                   leading=12, leftIndent=12)))
            story.append(KeepTogether(block + [Spacer(1, 3*mm)]))

    # ── Disclaimer ────────────────────────────────────────────────────
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))
    story.append(Paragraph(
        f"This report was generated by BlackPort v2.2.0 on {now}. "
        "It is intended for the exclusive use of the authorised recipient. "
        "All findings are based on active network probing of the target system. "
        "Handle as CONFIDENTIAL — do not distribute without authorisation.",
        ParagraphStyle("disc", fontName="Helvetica", fontSize=7,
                       textColor=C_MUTED, leading=11)))

    doc.build(story)

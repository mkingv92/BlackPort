# BlackPort v2.2.0
### Offensive Port Intelligence Engine

> For use only on hosts and networks you own or have explicit written permission to test.

---

## Overview

BlackPort is a fast, active-verification port scanner built for internal network reconnaissance and penetration testing. It combines a high-speed TCP sweep with a parallel plugin phase that actively probes each open service — not just identifying it, but confirming exploitability.

**Metasploitable benchmark:** 48 ports in 7.7s (`--top-100`), 65535 ports in 97s (`--full`), 14 CRITICAL findings actively confirmed.

---

## Quick Start

```bash
# Fast curated scan — 48 high-value ports, ~7s
python main.py 192.168.1.1 --top-100

# Broad curated scan — 200+ ports including databases and APIs, ~15s
python main.py 192.168.1.1 --top-500

# Top 1000 sequential ports
python main.py 192.168.1.1 --top-1000

# Full range — all 65535 ports, ~97s
python main.py 192.168.1.1 --full

# Specific range
python main.py 192.168.1.1 80 8080

# Network scan — discovers live hosts then scans each
python main.py 192.168.1.0/24 --top-100

# Save reports to a specific directory
python main.py 192.168.1.1 --top-100 --output-dir ~/reports

# Generate PDF report (client-deliverable, add --pdf to any scan)
python main.py 192.168.1.1 --top-100 --pdf

# Full scan with PDF saved to reports folder
python main.py 192.168.1.1 --full --pdf --output-dir ~/reports
```

---

## Architecture

BlackPort runs in three sequential phases per target:

```
Phase 1 — TCP Sweep (400 threads, 0.5s timeout)
  Connect to every port in the list/range
  Banner grab → service fingerprinting → CVE lookup
  No plugins run here — keeps the sweep pool clean

Phase 2 — Plugin Phase (10 workers, parallel)
  Active verification against all open non-SMB ports
  Each plugin opens its own connection and probes the service
  Results merged back; risk escalated if plugin confirms exploit

Phase 3 — SMB Post-Sweep (sequential)
  SMB/NetBIOS enumerated after all threads complete
  Avoids connection-flood false negatives on ports 139/445
```

**Timing (Metasploitable, 65535 ports):**
```
Sweep:   82.9s
Plugins:  6.3s  (22× faster than sequential)
SMB:      0.6s
Total:   97s
```

---

## Scan Profiles

| Profile | Ports | Time (typical) | Use case |
|---|---|---|---|
| `--top-100` | 48 curated | ~7s | Quick triage, CTF, known targets |
| `--top-500` | 200+ curated | ~15s | Broader recon including databases/APIs |
| `--top-1000` | 1–1000 sequential | ~10s | Standard pentesting range |
| `--full` | 1–65535 | ~97s | Full discovery, no stone unturned |
| `start end` | Custom range | varies | Targeted follow-up |

---

## Plugins (23 active)

Each plugin opens a real connection and attempts active verification — not just banner matching.

| Plugin | Port(s) | What it confirms |
|---|---|---|
| FTP | 21 | Anonymous login, vsFTPd 2.3.4 backdoor shell on 6200 |
| SSH | 22 | Version, CVE match |
| Telnet | 23 | No-auth shell accepted |
| SMTP | 25 | VRFY enabled, open relay |
| HTTP | 80, 8080, 8180 | Title, headers, tech stack |
| TLS | 443, 8443 | Version, cipher strength, cert validity |
| SMB | 139, 445 | SMBv1 detection, signing, share enumeration |
| rexec | 512 | .rhosts bypass attempt |
| rlogin | 513 | No-auth connection accepted |
| rsh | 514 | No-auth command execution |
| Java RMI | 1099 | Registry responding, no-auth |
| Bindshell | 1524 | Banner confirms root shell |
| NFS | 2049 | Export list, world-readable check |
| MySQL | 3306 | Root no-password login |
| distccd | 3632 | RCE via ARGV injection (`id` executed) |
| PostgreSQL | 5432 | Auth method, version |
| VNC | 5900 | Auth type, no-auth check |
| X11 | 6000 | No-auth display access |
| IRC | 6667, 6697 | UnrealIRCd backdoor probe |
| AJP/Ghostcat | 8009 | Unauthenticated file read confirmed |
| Tomcat Manager | 8180, 8080 | Default credentials (tomcat:tomcat) |
| DRb | 8787 | Ruby DRb service, $SAFE mode detection |

---

## Output

Every scan produces three files by default. Add `--pdf` for a fourth:

| Format | Flag | Contents |
|---|---|---|
| `.json` | always | Full structured results — all plugin output, CVE data, banners, risk scores |
| `.csv` | always | Flat export for spreadsheet analysis or SIEM ingestion |
| `.html` | always | Interactive dark-theme report with severity chart, per-finding CVE details, and remediation |
| `.pdf` | `--pdf` | Print-ready report — cover page, findings table, recommendations. Client-deliverable |

Reports are named `blackport_{target}_{timestamp}.{ext}` and saved to `--output-dir` (default: current directory).

### PDF Report Structure

The PDF is a 3-page professional document built with ReportLab:

- **Page 1** — Cover: target metadata, overall risk, exposure score, severity summary cards, donut chart
- **Page 2** — Findings table: port, service+banner, risk badge, CVE ID + CVSS score, active verification results, per-row remediation
- **Page 3** — Recommendations: all findings grouped by risk level with specific, actionable guidance per service

Every page has a running header (target + "BLACKPORT Security Report") and footer (timestamp, page number, confidentiality notice).

---

## CVE Database

`cve_db.py` contains 80+ static entries covering:

FTP (vsFTPd, ProFTPD, FileZilla), SSH (OpenSSH, Dropbear), HTTP (Apache 2.0/2.2, IIS 5/6, nginx), Tomcat (all versions, Ghostcat), SMB (EternalBlue, SambaCry), MySQL/MariaDB, PostgreSQL, SMTP (Postfix, Sendmail, Exim, Exchange/ProxyLogon), RDP (BlueKeep), VNC (RealVNC, UltraVNC), DNS (BIND), Redis, MongoDB, Docker (runc escape), Java RMI, JBoss, WebLogic, SNMP, distccd, UnrealIRCd, Telnet, Asterisk/SIP, CUPS, HP JetDirect.

Used as fallback when NVD API (`--nvd`) is unavailable. CVSS scores are v3 base scores where available.

---

## Flags Reference

```
Scan profiles:
  --top-100       48 curated high-value ports (~7s)
  --top-500       200+ ports including databases/APIs (~15s)
  --fast          Ports 1-100 sequential
  --top-1000      Ports 1-1000 sequential (~10s)
  --full          Full 1-65535 scan (~97s)

Tuning:
  --threads N     Sweep thread count (default: auto-scaled)
  --timeout N     Socket timeout in seconds (default: 1.0)
  --delay N       Delay between plugin checks (default: 0)

Output:
  --output-dir    Directory for report files (default: .)
  --pdf           Generate PDF report in addition to HTML/JSON/CSV
  --json          Print JSON results to stdout
  --quiet         Suppress progress output

Other:
  --nvd           Enrich with live NVD CVE API data
  --log           Write structured log to ~/.blackport/blackport.log
  --diff f1 f2    Compare two scan JSON files
  --version       Show version
```

---

## Project Structure

```
BlackPort-main/
├── main.py                    # Entry point, argument parsing, multi-host
├── blackport/
│   ├── scanner.py             # Three-phase scan engine
│   ├── fingerprint_db.py      # 200-entry service fingerprint database
│   └── os_detect.py           # OS detection via TTL + banner heuristics
├── plugins/
│   ├── plugin_base.py         # Base class for all plugins
│   ├── ftp_plugin.py
│   ├── ssh_plugin.py
│   ├── telnet_plugin.py
│   ├── smtp_plugin.py
│   ├── http_plugin.py
│   ├── tls_plugin.py
│   ├── smb_plugin.py
│   ├── rservices_plugin.py    # rexec/rlogin/rsh
│   ├── rmi_plugin.py
│   ├── bindshell_plugin.py
│   ├── nfs_plugin.py
│   ├── mysql_plugin.py
│   ├── distccd_plugin.py
│   ├── postgresql_plugin.py
│   ├── vnc_plugin.py
│   ├── x11_plugin.py
│   ├── irc_plugin.py
│   ├── ajp_plugin.py
│   ├── tomcat_plugin.py
│   └── drb_plugin.py
├── cve_db.py                  # 80+ static CVE entries
├── cve_lookup.py              # NVD API integration + local cache
├── html_report.py             # Professional HTML report generator
├── pdf_report.py              # PDF report generator (requires reportlab)
├── multi_host_report.py       # Network-wide summary report
├── enum_modules.py            # HTTP title, SMB shares, FTP anon
├── exploit_indicators.py      # Static exploit hint database
├── tls_enum.py                # TLS/SSL certificate analysis
├── diff.py                    # Scan comparison tool
└── requirements.txt
```

---

## Confirmed Findings on Metasploitable 2

| Port | Service | Finding | Severity |
|---|---|---|---|
| 21 | vsFTPd 2.3.4 | Backdoor shell on port 6200 | CRITICAL |
| 23 | Telnet | No-auth shell | CRITICAL |
| 80 | Apache 2.2.8 | CVE-2011-3192, PHP 5.2.4 | CRITICAL |
| 139 | NetBIOS | SMBv1 detected | CRITICAL |
| 445 | SMB | SMBv1 + EternalBlue | CRITICAL |
| 513 | rlogin | No-auth connection accepted | CRITICAL |
| 514 | rsh | No-auth command execution | CRITICAL |
| 1099 | Java RMI | No-auth registry | CRITICAL |
| 1524 | Bindshell | Root shell banner confirmed | CRITICAL |
| 2049 | NFS | / exported to * | CRITICAL |
| 3306 | MySQL | Root no-password login | CRITICAL |
| 3632 | distccd | RCE confirmed: uid=1(daemon) | CRITICAL |
| 8009 | AJP | Ghostcat file read (8774 bytes) | CRITICAL |
| 8180 | Tomcat | Default creds tomcat:tomcat | CRITICAL |

**14 CRITICAL / 5 HIGH / 2 MEDIUM / 9 LOW — Exposure Score: 10/10**

---

## Requirements

```
pip install colorama requests paramiko reportlab
```

`reportlab` is only required for `--pdf`. All other features work without it.

Python 3.8+. No root/sudo required for TCP scanning.

---

*BlackPort is a learning and research tool. Use responsibly.*

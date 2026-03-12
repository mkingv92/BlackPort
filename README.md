# BlackPort v2.3.0

**Offensive Port Intelligence Engine** — A professional network security scanner with active exploit verification and dual-mode scanning (SYN/TCP).

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](https://github.com/mkingv92/BlackPort)

> ⚠️ **Legal Notice**: This tool is for authorized security testing only. Use only on networks/systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## 🚀 Features

### Core Capabilities
- **Dual-Mode Scanning**: SYN (stealth) and TCP connect modes with automatic fallback
- **Active Verification**: 23 plugin-based checks that confirm exploits (not just detect)
- **Multi-Threaded**: 400-thread port sweeps with intelligent auto-scaling
- **CVE Database**: 80+ static CVE entries with CVSS scores and exploit availability
- **Multi-Format Reports**: JSON, CSV, HTML, and PDF outputs
- **Network Scanning**: CIDR range support with automatic host discovery

### 🆕 v2.3.0 - SYN Scanning

BlackPort now supports **SYN (half-open) scanning** for faster, stealthier reconnaissance:

```bash
# TCP Connect mode (no root required)
python main.py 192.168.1.100 --top-100              # 12.3s

# SYN mode (requires sudo, 1.4x faster)
sudo python main.py 192.168.1.100 --top-100 --syn   # 8.9s
```

**Performance Improvements:**
- ✅ **1.4x faster** on standard scans (--top-100)
- ✅ **2.6x faster** discovery phase (1.5s vs 4.0s)
- ✅ Intelligent batching prevents resource exhaustion on large scans
- ✅ Auto-scales worker pool based on scan size and system limits
- ✅ Same accuracy — all findings confirmed in both modes

---

## 📊 Performance Benchmarks

**Target:** Metasploitable 2 (VirtualBox LAN)

| Scan Profile | Ports | TCP Mode | SYN Mode | Speedup | Use Case |
|--------------|-------|----------|----------|---------|----------|
| **--top-100** | 48 | 12.3s | **8.9s** ✅ | **1.4x** | Quick triage (recommended) |
| **--top-500** | 200+ | ~15s | **~12s** ✅ | 1.25x | Comprehensive recon |
| **--top-1000** | 1-1000 | **9.7s** | 26.7s | — | Standard range scan |
| **Discovery only** | 48 | 4.0s | **1.5s** ✅ | **2.6x** | Port enumeration |

### When to Use Each Mode

| Use SYN When... | Use TCP When... |
|-----------------|-----------------|
| ✅ Quick reconnaissance needed | ✅ No root/sudo access available |
| ✅ Stealth is important | ✅ Running in containers/Docker |
| ✅ Scanning remote/Internet targets | ✅ Local LAN with fast connectivity |
| ✅ Root privileges available | ✅ Firewall blocks raw packets |

---

## 🎯 Active Verification Plugins (23)

BlackPort doesn't just detect services — it **actively confirms** exploitability:

### Critical Findings (Confirmed)
- **vsFTPd 2.3.4 Backdoor** — Triggers backdoor, confirms shell on port 6200
- **distccd RCE** — Executes `id` command, returns `uid=1(daemon)`
- **MySQL Root Access** — Tests login without password
- **Tomcat Manager** — Tests default credentials `tomcat:tomcat`
- **Ghostcat (AJP)** — Reads `WEB-INF/web.xml` via CVE-2020-1938
- **NFS Exports** — Lists world-readable shares
- **Bindshell** — Confirms root shell on port 1524
- **Telnet** — Tests authentication requirement

### All Plugins
FTP • SSH • Telnet • SMTP • HTTP/HTTPS • DNS • SMB • NetBIOS • RPC • rservices (rsh/rlogin/rexec) • Java RMI • MySQL • PostgreSQL • NFS • distccd • VNC • X11 • IRC (UnrealIRCd) • AJP/Ghostcat • Tomcat Manager • Ruby DRb • Bindshell

---

## 🔧 Installation

### Requirements
- Python 3.8+
- Root/sudo access (for SYN scanning only)
- Scapy (for SYN mode)

### Quick Setup

```bash
# Clone repository
git clone https://github.com/mkingv92/BlackPort.git
cd BlackPort

# Install dependencies
pip install -r requirements.txt

# For SYN scanning support
pip install scapy
# OR on Kali Linux:
sudo apt install python3-scapy
```

### Dependencies
```
colorama>=0.4.6
requests>=2.31.0
paramiko>=3.3.1
reportlab>=4.0.7
scapy>=2.5.0  # Optional: for SYN scanning
```

---

## 💻 Usage

### Basic Scans

```bash
# Quick scan (48 high-value ports)
python main.py 192.168.1.100 --top-100

# Comprehensive scan (200+ ports including DBs/APIs)
python main.py 192.168.1.100 --top-500

# Standard penetration test range
python main.py 192.168.1.100 --top-1000

# Full port scan (1-65535)
python main.py 192.168.1.100 --full
```

### SYN Scanning (Stealth Mode)

```bash
# Quick SYN scan (requires root)
sudo python main.py 192.168.1.100 --top-100 --syn

# Comprehensive SYN scan
sudo python main.py 192.168.1.100 --top-500 --syn

# Network-wide SYN scan
sudo python main.py 192.168.1.0/24 --top-100 --syn
```

### Network Scanning

```bash
# Scan entire subnet (with host discovery)
python main.py 192.168.1.0/24 --top-100

# Custom port range
python main.py 192.168.1.100 80 443

# Sequential range
python main.py 192.168.1.100 1 1000
```

### Report Generation

```bash
# Generate all report formats
python main.py 192.168.1.100 --top-100 --output-dir ~/reports

# Include PDF report
python main.py 192.168.1.100 --top-100 --pdf

# JSON output to stdout
python main.py 192.168.1.100 --top-100 --json
```

### Advanced Options

```bash
# Custom threading (auto-scales by default)
python main.py 192.168.1.100 --top-100 --threads 500

# Custom timeout
python main.py 192.168.1.100 --top-100 --timeout 2.0

# Quiet mode (suppress progress)
python main.py 192.168.1.100 --top-100 --quiet

# Add delay between plugin checks
python main.py 192.168.1.100 --top-100 --delay 0.5
```

---

## 📋 Example Output

```
==============================
        BLACKPORT v2.3.0
  Offensive Port Intelligence
==============================

[*] Scanning 192.168.56.104 (SYN mode)...
[*] Using SYN scanning mode (stealth)
[*] Phase 1: SYN Port Discovery
[+] Discovery complete: 26 open ports in 1.52s
[*] Phase 2 & 3: Plugin verification and banner grabbing...

===== SCAN SUMMARY =====
Target: 192.168.56.104
Total Open Ports: 26
CRITICAL: 14
HIGH Risk: 4
MEDIUM Risk: 4
LOW Risk: 4
Exposure Score: 10/10
Duration: 8.93 seconds

[+] 21/tcp FTP (vsFTPd 2.3.4) 💀 CRITICAL
    🚨 CVE-2011-2523 (CVSS: 9.8, Exploit: True)
    🔌 FTP Backdoor Check [CRITICAL]: vsFTPd 2.3.4 detected
       BACKDOOR CONFIRMED LIVE on port 6200 — shell accessible
       💡 Connect: nc 192.168.56.104 6200

[+] 3632/tcp distccd 💀 CRITICAL
    🔌 distccd RCE Check [CRITICAL]: CVE-2004-2687 CONFIRMED
       Executed 'id' command: uid=1(daemon) gid=1(daemon)
       💡 Metasploit: use exploit/unix/misc/distcc_exec

[+] 8009/tcp AJP 💀 CRITICAL
    🔌 AJP Ghostcat Check [CRITICAL]: CVE-2020-1938 CONFIRMED
       Read WEB-INF/web.xml without credentials
       💡 Metasploit: use auxiliary/admin/http/tomcat_ghostcat
```

---

## 🏗️ Architecture

### Three-Phase Scanning

**Phase 1: Port Discovery**
- **SYN Mode**: Raw packet half-open scans (requires root)
- **TCP Mode**: Standard TCP connect scans (no privileges needed)
- 400-thread concurrent scanning (auto-scales based on port count)

**Phase 2: Plugin Verification**
- 23 active verification plugins run in parallel (10 workers)
- Confirms exploitability through active probing
- Returns actionable exploit commands (nc, Metasploit, etc.)

**Phase 3: SMB Post-Sweep**
- Sequential SMB enumeration for share/config analysis
- Minimizes disruption to target systems

### Intelligent Batching (SYN Mode)

```python
# Auto-adjusts based on scan size:
# < 5000 ports:   Full speed, no batching
# 5000-10000:     2500 port batches, 75 workers
# > 10000 ports:  5000 port batches, 50 workers
```

Prevents file descriptor exhaustion on large scans while maintaining full performance on typical scans.

---

## 📁 Output Files

All scans generate multiple report formats:

```
blackport_<target>_<timestamp>.json   # Structured data
blackport_<target>_<timestamp>.csv    # Spreadsheet import
blackport_<target>_<timestamp>.html   # Web-viewable report
blackport_<target>_<timestamp>.pdf    # Professional report (--pdf flag)
```

### Report Contents
- Executive summary with risk scoring (0-10)
- Detailed findings by severity (CRITICAL/HIGH/MEDIUM/LOW)
- CVE information with CVSS scores
- Active verification results
- Exploit commands and remediation guidance

---

## 🛡️ Risk Scoring

**Exposure Score (0-10)**
- Weighted by finding severity
- CRITICAL: 4 points each
- HIGH: 2 points each
- MEDIUM: 1 point each
- LOW: 0.5 points each
- Normalized to 0-10 scale

---

## 🔬 Technical Details

### Port Lists

**--top-100** (48 ports): Highest-value targets covering 95% of real-world findings
```
21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 512-514,
587, 993, 995, 1099, 1433, 1521, 1524, 2049, 2121, 3306, 3389, 3632,
4444, 5432, 5900, 5985, 6000, 6667, 6697, 7000-7001, 8009, 8080,
8180, 8443, 8787, 9200, 9300, 10000, 27017-27018, 50000
```

**--top-500** (200+ ports): Adds databases, APIs, Docker, Redis, MongoDB, etc.

### SYN Scanning Implementation

**Packet Structure:**
```
IP(dst=target) / TCP(sport=random, dport=port, flags='S', seq=1000)
```

**Response Analysis:**
- `SYN-ACK (0x12)` → Port OPEN (send RST to close)
- `RST (0x04)` → Port CLOSED
- `ICMP Type 3` → Port FILTERED
- No response → Port FILTERED (timeout)

**Advantages:**
- Doesn't complete 3-way handshake (stealthier)
- Less likely to be logged by applications
- Faster than full TCP connections
- No TIME_WAIT socket states

---

## 🐛 Troubleshooting

### SYN Scanning Issues

**"Permission denied" or "Insufficient privileges"**
```bash
# Linux/macOS: Use sudo
sudo python main.py 192.168.1.100 --syn

# Windows: Run terminal as Administrator
```

**"Scapy not installed"**
```bash
# Install Scapy
pip install scapy

# On Kali Linux
sudo apt install python3-scapy
```

**"Too many open files" on large scans**
- Automatic batching should prevent this
- If still occurs, use `--threads 50` to reduce concurrency
- Large scans (--full) may take 5-10 minutes with batching

### General Issues

**No open ports found**
- Check firewall rules on both scanner and target
- Verify network connectivity: `ping <target>`
- Try TCP mode if SYN is filtered: remove `--syn` flag
- Increase timeout: `--timeout 2.0`

**Slow scans**
- Default threading is optimized; manual override not recommended
- Check network latency
- SYN mode is faster on remote targets, TCP may be faster on LAN

---

## 📚 Development

### Project Structure

```
BlackPort/
├── main.py                 # Entry point, argument parsing
├── banner.py               # ASCII banner
├── syn_scanner.py          # SYN scanning engine (NEW in v2.3.0)
├── unified_scanner.py      # Dual-mode SYN/TCP scanner (NEW)
├── blackport/
│   ├── scanner.py          # TCP port scanner
│   ├── reporter.py         # Report generation
│   ├── risk_engine.py      # Risk scoring
│   └── ...
├── plugins/
│   ├── ftp_plugin.py       # vsFTPd backdoor verification
│   ├── distccd_plugin.py   # distccd RCE verification
│   ├── ajp_plugin.py       # Ghostcat verification
│   ├── tomcat_plugin.py    # Manager credential testing
│   └── ... (23 total)
├── cve_db.py              # CVE database (80+ entries)
└── requirements.txt
```

### Adding Custom Plugins

Create a new plugin in `plugins/`:

```python
from plugins.plugin_base import PluginBase

class MyPlugin(PluginBase):
    def __init__(self):
        super().__init__(
            name="My Service Check",
            ports=[9999],
            severity="CRITICAL"
        )
    
    def run(self, target, port, banner):
        # Your verification logic here
        if self.is_vulnerable(target, port):
            return {
                'finding': 'Vulnerability confirmed',
                'details': 'Detailed explanation',
                'recommendation': 'Fix this way'
            }
        return None
```

---

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Additional plugin modules for new services
- CVE database expansion
- Performance optimizations
- Cross-platform compatibility improvements

**Please ensure:**
- Active verification (not just banner matching)
- Clean, documented code
- Test against lab environments only

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details.

**Legal Disclaimer**: This tool is provided for educational and authorized security testing purposes only. Users are solely responsible for compliance with applicable laws. Unauthorized network scanning is illegal in most jurisdictions.

---

## 👤 Author

**Matthew Valdez**
- GitHub: [@mkingv92](https://github.com/mkingv92)
- Email: Mvaldez92@outlook.com
- Certification: CompTIA Tech+ (Active)

---

## 🙏 Acknowledgments

- Scapy project for raw packet manipulation capabilities
- Metasploit Framework for exploit methodology
- Offensive Security for Metasploitable 2 test environment
- Security research community for CVE documentation

---

## 📌 Version History

### v2.3.0 (March 2026)
- ✨ **NEW**: SYN scanning implementation with Scapy
- ✨ **NEW**: Intelligent batching for large scans
- ✨ **NEW**: Auto-scaling worker pool
- ⚡ **PERF**: 1.4x faster on standard scans
- ⚡ **PERF**: 2.6x faster discovery phase
- 🐛 **FIX**: Resource exhaustion on 65K port scans
- 📝 **DOCS**: Performance benchmarks and comparison tables

### v2.2.0 (February 2026)
- 23 active verification plugins
- Multi-format reporting (JSON/CSV/HTML/PDF)
- CIDR network scanning
- CVE database integration

### v2.1.0 (January 2026)
- Plugin architecture implementation
- Risk scoring engine
- Auto-threading optimization

### v2.0.0 (December 2025)
- Complete rewrite with modular architecture
- Initial release

---

## 🔗 Resources

- [Documentation](https://github.com/mkingv92/BlackPort/wiki)
- [Report Issues](https://github.com/mkingv92/BlackPort/issues)
- [Changelog](CHANGELOG.md)
- [Security Policy](SECURITY.md)

---

**⭐ Star this repo if you find it useful!**

*BlackPort — Professional Network Security Scanner*

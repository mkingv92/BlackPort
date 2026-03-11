# =====================================================================
# File: blackport/scanner.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import socket
import json
import csv
import time
import importlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from cve_lookup import load_cve_db, match_cves
from cve_db import check_cve
from enum_modules import get_http_title, check_ftp_anonymous, enum_smb_shares
from blackport.fingerprint_db import fingerprint_banner, service_from_port
from exploit_indicators import check_exploit_indicators
from html_report import generate_html_report
try:
    from pdf_report import generate_pdf_report
    _PDF_AVAILABLE = True
except ImportError:
    _PDF_AVAILABLE = False
from tls_enum import get_tls_details
from colorama import Fore, Style, init
init(autoreset=True)

# Dynamically load all plugins in plugins folder
plugins = []
plugin_folder = os.path.join(os.path.dirname(__file__), "..", "plugins")
for file in sorted(os.listdir(plugin_folder)):
    if file.endswith("_plugin.py"):
        module_name = f"plugins.{file[:-3]}"
        try:
            module = importlib.import_module(module_name)
            for attr in dir(module):
                obj = getattr(module, attr)
                if isinstance(obj, type) and hasattr(obj, "applicable_services") and hasattr(obj, "run"):
                    if obj.__name__ != "PluginBase":
                        plugins.append(obj())
        except Exception as e:
            print(f"[!] Failed to load plugin {file}: {e}")

HIGH_RISK_PORTS   = {21, 22, 23, 80, 445, 3389}
MEDIUM_RISK_PORTS = {443, 8080}
SMB_PORTS         = {139, 445}

# Number of parallel workers for the plugin phase.
# Intentionally kept lower than the sweep thread count — plugins open
# their own TCP connections and we don't want to flood the target.
PLUGIN_WORKERS = 10


class PortScanner:

    def __init__(self, target, start_port, end_port, threads=200, timeout=3,
                 output_dir=None, port_list=None, pdf=False):
        self.target        = target
        self.start_port    = start_port
        self.end_port      = end_port
        self.threads       = threads
        self.timeout       = timeout            # used by plugins
        self.sweep_timeout = min(timeout, 0.5)  # fast connect-only timeout for sweep
        self.output_dir    = output_dir or "."
        self.results       = []
        self.pdf           = pdf
        # Curated list takes priority over start/end range
        if port_list:
            self.ports = port_list
        else:
            self.ports = range(self.start_port, self.end_port + 1)

    def color_risk(self, risk):
        if risk == "CRITICAL":
            return Fore.MAGENTA + risk + Style.RESET_ALL
        elif risk == "HIGH":
            return Fore.RED + risk + Style.RESET_ALL
        elif risk == "MEDIUM":
            return Fore.YELLOW + risk + Style.RESET_ALL
        elif risk == "LOW":
            return Fore.GREEN + risk + Style.RESET_ALL
        return risk

    def grab_banner(self, sock, port):
        try:
            sock.settimeout(2)
            try:
                banner = sock.recv(2048)
                if banner:
                    return banner.decode(errors="ignore").strip()
            except Exception:
                pass

            if port in {80, 8080, 8180, 8443}:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            elif port in {25, 587}:
                sock.sendall(b"EHLO blackport\r\n")
            elif port == 21:
                sock.sendall(b"\r\n")
            elif port in {6667, 6697, 7000}:
                sock.sendall(b"NICK bp\r\nUSER bp 0 * :bp\r\n")

            try:
                banner = sock.recv(2048)
                if banner:
                    return banner.decode(errors="ignore").strip()
            except Exception:
                pass

        except Exception:
            pass
        return None

    # NOTE: scan_port() — Phase 1 only: connect, banner grab, fingerprint, CVE lookup.
    # Plugin execution has been removed from this method and moved to
    # _run_plugins_for_port() which runs in a separate parallel phase
    # after the sweep completes. This keeps the sweep thread pool clean
    # and allows the plugin phase to be independently parallelised.
    def scan_port(self, port, cve_db):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.sweep_timeout)
                try:
                    s.connect((self.target, port))
                except Exception:
                    return None

                banner = self.grab_banner(s, port)

                # --- Fingerprinting: 200-entry DB ---
                service_hint = service_from_port(port)
                service, product, version, confidence = fingerprint_banner(
                    port, banner, service_hint=service_hint
                )
                if not service or service == "Unknown":
                    service = service_hint

                # --- Base risk ---
                if port in HIGH_RISK_PORTS:
                    risk = "HIGH"
                elif port in MEDIUM_RISK_PORTS:
                    risk = "MEDIUM"
                else:
                    risk = "LOW"

                exploit_flag = check_exploit_indicators(product, version)
                cve_matches  = match_cves(banner, cve_db) if banner else []

                http_title  = None
                tls_details = None

                if service == "HTTPS" or port in {443, 8443, 9443, 993, 995, 465, 587}:
                    tls_details = get_tls_details(self.target, port, server_name=self.target)
                elif service == "HTTP":
                    http_title = get_http_title(self.target, port)

                product = product.strip("()") if product else None
                version = version.strip("()") if version else None

                # --- CVE risk override ---
                cve_info = check_cve(product, version) if product and version else None
                if cve_info:
                    if cve_info["cvss"] >= 9:
                        risk = "CRITICAL"
                    elif cve_info["cvss"] >= 7:
                        risk = "HIGH"
                    elif cve_info["cvss"] >= 4:
                        risk = "MEDIUM"
                    else:
                        risk = "LOW"

                return {
                    "port":              port,
                    "service":           service,
                    "banner":            banner,
                    "product":           product,
                    "version":           version,
                    "confidence":        confidence,
                    "risk":              risk,
                    "exploit_indicator": exploit_flag,
                    "cve_matches":       cve_matches,
                    "http_title":        http_title,
                    "anonymous_ftp":     None,
                    "smb_shares":        None,   # filled by _smb_post_sweep
                    "tls":               tls_details,
                    "cve_info":          cve_info,
                    "plugins":           [],     # filled by _plugin_phase
                }

        except Exception:
            return None

    # NOTE: _run_plugins_for_port() — runs all matching plugins for a single
    # port result dict. Called concurrently by _plugin_phase(). Returns the
    # updated result dict so the caller can merge it back thread-safely.
    def _run_plugins_for_port(self, r):
        service        = r.get("service", "Unknown")
        port           = r["port"]
        banner         = r.get("banner")
        plugin_results = []

        for plugin in plugins:
            if service.upper() in [s.upper() for s in plugin.applicable_services]:
                try:
                    result = plugin.run(self.target, port, banner)
                    if result:
                        plugin_results.append(result)
                except Exception:
                    pass

        # Escalate risk based on plugin findings
        risk = r["risk"]
        if plugin_results:
            plugin_risks = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            risk_levels  = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            current      = plugin_risks.get(risk, 0)
            max_p        = max(plugin_risks.get(pr["risk"], 0) for pr in plugin_results)
            if max_p > current:
                risk = risk_levels[max_p]

        # Return a copy with updated fields — avoids mutating shared state
        # while other threads are still running
        return {**r, "plugins": plugin_results, "risk": risk}

    # NOTE: _plugin_phase() — Phase 2: run all plugins in parallel.
    # Uses a separate, smaller thread pool (PLUGIN_WORKERS=10) so plugins
    # don't starve each other's socket timeouts. SMB ports are excluded
    # here because they get their own post-sweep pass.
    def _plugin_phase(self):
        # Separate SMB ports — they need special handling in _smb_post_sweep
        non_smb = [r for r in self.results if r.get("port") not in SMB_PORTS]
        smb     = [r for r in self.results if r.get("port") in SMB_PORTS]

        if not non_smb:
            return

        print(f"{Fore.CYAN}[*] Running {len(non_smb)} plugin checks in parallel "
              f"(workers={PLUGIN_WORKERS})...{Style.RESET_ALL}")

        updated = {}
        with ThreadPoolExecutor(max_workers=PLUGIN_WORKERS) as pool:
            future_to_port = {
                pool.submit(self._run_plugins_for_port, r): r["port"]
                for r in non_smb
            }
            done = 0
            for future in as_completed(future_to_port):
                done += 1
                print(f"  Plugin phase: {done}/{len(non_smb)}", end="\r")
                try:
                    result = future.result()
                    updated[result["port"]] = result
                except Exception:
                    pass
        print()

        # Merge updated results back — replace original entries in-place
        self.results = [
            updated.get(r["port"], r)
            for r in self.results
            if r.get("port") not in SMB_PORTS
        ] + smb

    def _smb_post_sweep(self):
        """
        Run SMB enumeration sequentially AFTER the plugin phase.
        Avoids thread contention that caused intermittent CRITICAL→LOW flips.
        SMB plugins also run here so they have access to enumeration data.
        """
        for r in self.results:
            if r.get("port") not in SMB_PORTS:
                continue
            try:
                smb_data = enum_smb_shares(self.target)
                if not smb_data:
                    continue

                r["smb_shares"] = smb_data
                version = smb_data.get("version")
                signing = smb_data.get("signing")

                if version == "SMBv1":
                    r["risk"] = "CRITICAL"
                elif version in ("SMBv2", "SMBv3") and signing is False:
                    r["risk"] = "HIGH"
                elif version in ("SMBv2", "SMBv3") and signing is True:
                    r["risk"] = "MEDIUM"

                # Run SMB plugins now that enumeration data is populated
                for plugin in plugins:
                    if "SMB" in [s.upper() for s in plugin.applicable_services]:
                        try:
                            result = plugin.run(self.target, r["port"], r.get("banner"))
                            if result:
                                r["plugins"] = [
                                    p for p in r.get("plugins", [])
                                    if p.get("plugin") != result.get("plugin")
                                ]
                                r["plugins"].append(result)
                                plugin_risks = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                                risk_levels  = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                                current      = plugin_risks.get(r["risk"], 0)
                                max_p        = plugin_risks.get(result["risk"], 0)
                                if max_p > current:
                                    r["risk"] = risk_levels[max_p]
                        except Exception:
                            pass
            except Exception:
                pass

    def generate_reports(self, duration):
        if not self.results:
            print("\nNo open ports found.")
            return

        os.makedirs(self.output_dir, exist_ok=True)
        timestamp     = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = os.path.join(self.output_dir, f"blackport_{self.target}_{timestamp}")

        with open(f"{base_filename}.json", "w") as json_file:
            json.dump(self.results, json_file, indent=4)

        fieldnames = []
        for row in self.results:
            for k in row.keys():
                if k not in fieldnames:
                    fieldnames.append(k)

        with open(f"{base_filename}.csv", "w", newline="") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self.results)

        critical = len([r for r in self.results if r["risk"] == "CRITICAL"])
        high     = len([r for r in self.results if r["risk"] == "HIGH"])
        medium   = len([r for r in self.results if r["risk"] == "MEDIUM"])
        low      = len([r for r in self.results if r["risk"] == "LOW"])

        cvss_scores = [r["cve_info"]["cvss"] for r in self.results if r.get("cve_info")]
        avg_cvss    = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        score       = round(min(avg_cvss + len(self.results) * 0.15, 10), 1)

        html_filename = f"{base_filename}.html"
        generate_html_report(self.results, self.target, duration, score, high, medium, low, html_filename)

        # PDF report
        if _PDF_AVAILABLE and self.pdf:
            pdf_filename = f"{base_filename}.pdf"
            try:
                generate_pdf_report(self.results, self.target, duration, score, high, medium, low, pdf_filename)
            except Exception as e:
                print(f"[!] PDF generation failed: {e}")

        print(Fore.CYAN + "\n\n===== SCAN SUMMARY =====" + Style.RESET_ALL)
        print(f"Target: {self.target}")
        print(f"Total Open Ports: {len(self.results)}")
        print(f"CRITICAL: {Fore.MAGENTA}{critical}{Style.RESET_ALL}")
        print(f"HIGH Risk: {Fore.RED}{high}{Style.RESET_ALL}")
        print(f"MEDIUM Risk: {Fore.YELLOW}{medium}{Style.RESET_ALL}")
        print(f"LOW Risk: {Fore.GREEN}{low}{Style.RESET_ALL}")
        print(f"Exposure Score: {score}/10")
        print(f"Duration: {duration} seconds")
        report_exts = ".json, .csv, .html"
        if _PDF_AVAILABLE and self.pdf:
            report_exts += ", .pdf"
        print(f"Reports saved as: {os.path.basename(base_filename)}{report_exts}")
        print()

        for r in self.results:
            colored_risk = self.color_risk(r["risk"])
            icon = {"CRITICAL": "💀", "HIGH": "🔥", "MEDIUM": "⚠️"}.get(r["risk"], "✅")

            product = (r.get("product") or "").strip("() ")
            version = (r.get("version") or "").strip("() ")
            service_line = f"[+] {r['port']}/tcp {r['service']:<10}"
            if product:
                service_line += f" ({product}"
                if version:
                    service_line += f" {version}"
                service_line += ")"
            service_line += f" {icon} {colored_risk}"
            print(service_line)

            cve_info = r.get("cve_info")
            if cve_info:
                print(f"    🚨 {r['risk']} - {cve_info['cve']}")
                print(f"       CVSS: {cve_info['cvss']}")
                print(f"       Exploit Available: {cve_info['exploit']}")
                print(f"       {cve_info['description']}")

            if r.get("banner"):
                print(f"    Banner: {r['banner']}")

            exploit = r.get("exploit_indicator")
            if exploit and not cve_info:
                print(f"    🚨 {exploit['severity']} - {exploit['description']} ({exploit['reference']})")

            for p in r.get("plugins", []):
                if p:
                    print(f"    🔌 {p['plugin']} [{p['risk']}]: {p['notes']}")
                    if p.get("exploit_hint"):
                        print(f"       💡 {p['exploit_hint']}")

    def scan(self):
        start_time  = time.time()
        ports       = list(self.ports)
        total_ports = len(ports)
        scanned     = 0

        print(f"\nStarting scan on {self.target}")
        print(f"Scanning {total_ports} port(s)...\n")

        cve_db = load_cve_db()

        # --- Phase 1: Port sweep (high thread count, no plugins) ---
        phase1_start = time.time()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_port, port, cve_db) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                scanned += 1
                print(f"Progress: {scanned}/{total_ports} ({scanned/total_ports*100:.1f}%)", end="\r")
                if result:
                    self.results.append(result)
        print()

        phase1_time = round(time.time() - phase1_start, 1)
        print(f"{Fore.CYAN}[*] Sweep complete — {len(self.results)} open port(s) found "
              f"[{phase1_time}s]{Style.RESET_ALL}")

        # --- Phase 2: Plugin checks (parallel, separate pool) ---
        if self.results:
            phase2_start = time.time()
            self._plugin_phase()
            phase2_time = round(time.time() - phase2_start, 1)
            print(f"{Fore.CYAN}[*] Plugin phase complete [{phase2_time}s]{Style.RESET_ALL}")

        # --- Phase 3: SMB post-sweep (sequential, reliable) ---
        if any(r.get("port") in SMB_PORTS for r in self.results):
            phase3_start = time.time()
            print(f"{Fore.CYAN}[*] Running SMB enumeration...{Style.RESET_ALL}")
            self._smb_post_sweep()
            phase3_time = round(time.time() - phase3_start, 1)
            print(f"{Fore.CYAN}[*] SMB complete [{phase3_time}s]{Style.RESET_ALL}")

        # Sort by risk then port
        risk_order   = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.results = sorted(
            self.results,
            key=lambda x: (risk_order.get(x["risk"], 4), x["port"])
        )

        duration = round(time.time() - start_time, 2)
        self.generate_reports(duration)
        return self.results

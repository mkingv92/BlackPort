import socket
import json
import csv
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from cve_lookup import load_cve_db, match_cves
from cve_db import check_cve
from enum_modules import get_http_title, check_ftp_anonymous, enum_smb_shares
from fingerprint_engine import fingerprint_service
from exploit_indicators import check_exploit_indicators
from html_report import generate_html_report
from colorama import Fore, Style, init
init(autoreset=True)


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC"

}


HIGH_RISK_PORTS = {21, 22, 23, 445, 3389}
MEDIUM_RISK_PORTS = {80, 443, 8080}


class PortScanner:
    def __init__(self, target, start_port, end_port, threads=200, timeout=1):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.results = []
        self.ports = range(self.start_port, self.end_port +1)

    def color_risk(self, risk):

        if risk == "CRITICAL":
            return Fore.MAGENTA + risk + Style.RESET_ALL
        elif risk == "HIGH":
            return Fore.RED + risk + Style.RESET_ALL
        elif risk == "MEDIUM":
            return Fore.YELLOW + risk + Style.RESET_ALL
        elif risk == "LOW":
            return Fore.GREEN + risk + Style.RESET_ALL
        else:
            return risk


    def grab_banner(self, sock, port):
        try:
            sock.settimeout(2)

            # STEP 1: Try passive receive FIRST
            try:
                banner = sock.recv(2048)
                if banner:
                    return banner.decode(errors="ignore").strip()
            except:
                pass

            # STEP 2: If nothing received, send protocol-specific probe
            if port == 80:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 25:
                sock.sendall(b"EHLO test\r\n")
            elif port == 21:
                sock.sendall(b"\r\n")

            try:
                banner = sock.recv(2048)
                if banner:
                    return banner.decode(errors="ignore").strip()
            except:
                pass

        except Exception:
            pass

        return None

    def scan_port(self, port, cve_db):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)

                # CONNECT MUST BE INSIDE THE WITH BLOCK
                try:
                    s.connect((self.target, port))
                except:
                    return None

                # Port is open
                banner = self.grab_banner(s, port)

                detected_service, product, version, confidence = fingerprint_service(port, banner)

                if detected_service:
                    service = detected_service
                else:
                    service = COMMON_SERVICES.get(port, "Unknown")

                if port in HIGH_RISK_PORTS:
                    risk = "HIGH"
                elif port in MEDIUM_RISK_PORTS:
                    risk = "MEDIUM"
                else:
                    risk = "LOW"

                exploit_flag = check_exploit_indicators(product, version)

                cve_matches = match_cves(banner, cve_db) if banner else []

                http_title = None
                ftp_anon = None
                smb_enum = None

                if service == "HTTP":
                    http_title = get_http_title(self.target, port)
                elif service == "FTP":
                    ftp_anon = check_ftp_anonymous(self.target)
                elif service == "SMB":
                    smb_enum = enum_smb_shares(self.target)

                product = product.strip("()") if product else None
                version = version.strip("()") if version else None

                # CVE-Based Risk Override (Proper Placement)
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
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "product": product,
                    "version": version,
                    "confidence": confidence,
                    "risk": risk,
                    "exploit_indicator": exploit_flag,
                    "cve_matches": cve_matches,
                    "http_title": http_title,
                    "anonymous_ftp": ftp_anon,
                    "smb_shares": smb_enum,
                    "cve_info": cve_info

                }

        except Exception:
            return None


    def generate_reports(self, duration):
        if not self.results:
            print("\nNo open ports found.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"blackport_{self.target}_{timestamp}"

        # JSON Export
        with open(f"{base_filename}.json", "w") as json_file:
            json.dump(self.results, json_file, indent=4)

        # CSV Export
        with open(f"{base_filename}.csv", "w", newline="") as csv_file:
           writer = csv.DictWriter(csv_file, fieldnames=self.results[0].keys())
           writer.writeheader()
           writer.writerows(self.results)

        # Summary
        critical = len([r for r in self.results if r["risk"] == "CRITICAL"])
        high = len([r for r in self.results if r["risk"] == "HIGH"])
        medium = len([r for r in self.results if r["risk"] == "MEDIUM"])
        low = len([r for r in self.results if r["risk"] == "LOW"])

        high_risk = high
        medium_risk = medium

        # CVSS-Based Exposure Scoring

        cvss_scores = [
            r["cve_info"]["cvss"]
            for r in self.results
            if r.get("cve_info")
        ]

        if cvss_scores:
            avg_cvss = sum(cvss_scores) / len(cvss_scores)
        else:
            avg_cvss = 0

        # Exposure factor based on attack surface size
        exposure_factor = len(self.results) * 0.15

        score = round(min(avg_cvss + exposure_factor, 10), 1)

        html_filename = f"{base_filename}.html"

        generate_html_report(
            self.results,
            self.target,
            duration,
            score,
            high,
            medium,
            low,
            html_filename
        )


        print(Fore.CYAN + "\n\n===== SCAN SUMMARY =====" + Style.RESET_ALL)
        print(f"Target: {self.target}")
        print(f"Total Open Ports: {len(self.results)}")
        print(f"CRITICAL: {Fore.MAGENTA}{critical}{Style.RESET_ALL}")
        print(f"HIGH Risk: {Fore.RED}{high}{Style.RESET_ALL}")
        print(f"MEDIUM Risk: {Fore.YELLOW}{medium}{Style.RESET_ALL}")
        print(f"LOW Risk: {Fore.GREEN}{low}{Style.RESET_ALL}")
        print(f"Exposure Score: {score}/10")
        print(f"Duration: {duration} seconds")
        print(f"Reports saved as: {base_filename}.json, .csv and .html")
        print()

        for r in self.results:
            colored_risk = self.color_risk(r["risk"])

            if r["risk"] == "CRITICAL":
                icon = "💀"
            elif r["risk"] == "HIGH":
                icon = "🔥"
            elif r["risk"] == "MEDIUM":
               icon = "⚠️"
            else:
                icon = "✅"


            service_line = f"[+] {r['port']}/tcp {r['service']:<10}"


            # Product + Version Formatting
            product = r.get("product")
            version = r.get("version")

            if product:
                product = product.strip("() ")
            if version:
                version = version.strip("() ")

            if product:
               service_line += f" ({product}"
               if version:
                   service_line += f" {version}"
               service_line += ")"


            service_line += f" {icon} {colored_risk}"

            print(service_line)

            # CVE Intelligence Lookup
            cve_info = r.get("cve_info")

            if cve_info:
                print(f"    🚨 {cve_info['severity']} - {cve_info['cve']}")
                print(f"       CVSS: {cve_info['cvss']}")
                print(f"       Exploit Available: {cve_info['exploit']}")
                print(f"       {cve_info['description']}")


            # Confidence Formatting (only if meaningful)
            if r.get("confidence") and r["confidence"] > 0:
                service_line += f" ({r['confidence']}% conf)"

            if r.get("banner"):
                print(f"    Banner: {r['banner']}")

            exploit = r.get("exploit_indicator")

            if r.get("exploit_indicator") and not cve_info:
                print(f"    🚨 {exploit['severity']} - {exploit['description']} ({exploit['reference']})")


    def scan(self):
        start_time = time.time()
        ports = range(self.start_port, self.end_port + 1)
        total_ports = len(ports)
        scanned = 0

        print(f"\nStarting scan on {self.target}")
        print(f"Scanning {total_ports} ports...\n")


        cve_db = load_cve_db()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
           futures = [executor.submit(self.scan_port, port, cve_db) for port in ports]

           for future in as_completed(futures):
                result = future.result()
                scanned += 1

                percent = (scanned / total_ports) * 100
                print(
                    f"Progress: {scanned}/{total_ports} ({percent:.1f}%)",
                    end="\r"
                )

                if result:
                    self.results.append(result)
        print()


        # Sort results
        risk_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3
        }

        self.results = sorted(
            self.results,
            key=lambda x: (risk_order[x["risk"]], x["port"])
        )

        duration = round(time.time() - start_time, 2)

        # Generate report ONCE
        self.generate_reports(duration)

        return self.results

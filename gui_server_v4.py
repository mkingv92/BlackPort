"""
MayheM-Sec Added

BlackPort local GUI v4.

Adds explicit Safe / Verify / Aggressive assessment policy selection to the
v3 dashboard while preserving localhost-only operation, scan history, report
viewing, and process cleanup.
"""

from __future__ import annotations

import json
import sys
from urllib.parse import urlparse

import gui_server_v3 as v3
from gui_server_v2 import HOST_RE, MODES, REPORT_DIR, ROOT, TCP_PROFILES, UDP_PROFILES

ASSESSMENT_PROFILES = {"safe", "verify", "aggressive"}

# MayheM-Sec Added: extend the existing v3 form without duplicating its layout.
HTML = v3.HTML.replace(
    '<label>Scan mode</label><select id="mode" onchange="syncMode()">',
    '<label>Assessment profile</label><select id="assessmentProfile">'
    '<option value="safe">Safe — no verification plugins</option>'
    '<option value="verify">Verify — reviewed non-destructive checks</option>'
    '<option value="aggressive">Aggressive — upstream active verification</option>'
    '</select>'
    '<label>Scan mode</label><select id="mode" onchange="syncMode()">',
).replace(
    'mode:el("mode").value,tcp_profile:',
    'mode:el("mode").value,assessment_profile:el("assessmentProfile").value,tcp_profile:',
)


class Handler(v3.Handler):
    """MayheM-Sec Added: v4 request handling with explicit assessment policy."""

    server_version = "BlackPortGUI/4.0"

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/":
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()

    def _start_scan(self, payload: dict) -> None:
        target = str(payload.get("target", "")).strip()
        mode = str(payload.get("mode", "tcp")).lower()
        assessment = str(payload.get("assessment_profile", "safe")).lower()
        tcp_profile = str(payload.get("tcp_profile", "top-100"))
        udp_profile = str(payload.get("udp_profile", "top-25"))

        if not target or len(target) > 253 or not HOST_RE.fullmatch(target):
            raise ValueError("Enter a valid IP address, hostname, or CIDR target")
        if mode not in MODES:
            raise ValueError("Unknown scan mode")
        if assessment not in ASSESSMENT_PROFILES:
            raise ValueError("Unknown assessment profile")
        if tcp_profile not in TCP_PROFILES:
            raise ValueError("Unknown TCP profile")
        if udp_profile not in UDP_PROFILES:
            raise ValueError("Unknown UDP profile")
        if mode in {"udp", "mixed"} and "/" in target:
            raise ValueError("UDP and mixed modes currently accept one IP address or hostname, not CIDR")

        try:
            udp_timeout = float(payload.get("udp_timeout", 1.0))
            udp_retries = int(payload.get("udp_retries", 2))
        except (TypeError, ValueError):
            raise ValueError("UDP timeout and retries must be numeric")
        if not 0.1 <= udp_timeout <= 10.0:
            raise ValueError("UDP timeout must be between 0.1 and 10 seconds")
        if not 1 <= udp_retries <= 5:
            raise ValueError("UDP retries must be between 1 and 5")

        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        command = [
            sys.executable,
            str(ROOT / "mayhem_scan.py"),
            target,
            "--mode", mode,
            "--assessment-profile", assessment,
            "--tcp-profile", tcp_profile,
            "--udp-profile", udp_profile,
            "--udp-timeout", str(udp_timeout),
            "--udp-retries", str(udp_retries),
            "--output-dir", str(REPORT_DIR),
        ]
        v3.STATE.start(command)
        self._json({"ok": True, "assessment_profile": assessment})


def run_gui(port: int = v3.DEFAULT_PORT, open_browser: bool = True) -> None:
    server = v3.ThreadingHTTPServer((v3.HOST, port), Handler)
    server.daemon_threads = True
    url = f"http://{v3.HOST}:{port}"
    print(f"[MayheM-Sec Added] BlackPort GUI v4: {url}")
    print("[MayheM-Sec Added] Default assessment profile: SAFE")
    print("[MayheM-Sec Added] Localhost only. Closing BlackPort stops the scan tree and listener.")
    if open_browser:
        v3.threading.Timer(0.35, lambda: v3.webbrowser.open(url, new=2)).start()
    try:
        server.serve_forever(poll_interval=0.4)
    except KeyboardInterrupt:
        pass
    finally:
        v3.STATE.stop()
        server.server_close()
        print("[MayheM-Sec Added] BlackPort GUI stopped; localhost listener closed.")


def main() -> None:
    parser = v3.argparse.ArgumentParser(description="BlackPort local graphical interface")
    parser.add_argument("--port", type=int, default=v3.DEFAULT_PORT)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")
    run_gui(args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()

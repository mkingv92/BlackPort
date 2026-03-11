# =====================================================================
# File: blackport/logger.py
# Notes:
# - This file is part of the BlackPort project.
# - Writes structured JSON logs to ~/.blackport/blackport.log
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import json
import os
import sys
from datetime import datetime

LOG_DIR  = os.path.expanduser("~/.blackport")
LOG_FILE = os.path.join(LOG_DIR, "blackport.log")
MAX_LOG_SIZE_MB = 10


class BlackPortLogger:
    def __init__(self, log_file=None, verbose=False):
        self.log_file = log_file or LOG_FILE
        self.verbose  = verbose
        self._ensure_dir()
        self._rotate_if_needed()

    def _ensure_dir(self):
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def _rotate_if_needed(self):
        """Rotate log file if it exceeds MAX_LOG_SIZE_MB."""
        if os.path.exists(self.log_file):
            size_mb = os.path.getsize(self.log_file) / (1024 * 1024)
            if size_mb > MAX_LOG_SIZE_MB:
                rotated = self.log_file + ".1"
                if os.path.exists(rotated):
                    os.remove(rotated)
                os.rename(self.log_file, rotated)

    def _write(self, entry):
        """Append a JSON log entry."""
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass  # Never let logging crash the scanner

    def scan_start(self, target, port_range, mode, threads, udp=False):
        entry = {
            "event":      "scan_start",
            "timestamp":  datetime.now().isoformat(),
            "target":     target,
            "port_range": port_range,
            "mode":       mode,
            "threads":    threads,
            "udp":        udp,
            "pid":        os.getpid(),
        }
        self._write(entry)
        if self.verbose:
            print(f"[LOG] Scan started: {target} ({mode})")

    def scan_complete(self, target, duration, open_ports, critical, high, medium, low, score):
        entry = {
            "event":      "scan_complete",
            "timestamp":  datetime.now().isoformat(),
            "target":     target,
            "duration_s": round(duration, 2),
            "open_ports": open_ports,
            "critical":   critical,
            "high":       high,
            "medium":     medium,
            "low":        low,
            "score":      score,
        }
        self._write(entry)
        if self.verbose:
            print(f"[LOG] Scan complete: {open_ports} ports, score {score}/10")

    def finding(self, target, port, service, risk, plugin=None, cve=None):
        entry = {
            "event":     "finding",
            "timestamp": datetime.now().isoformat(),
            "target":    target,
            "port":      port,
            "service":   service,
            "risk":      risk,
        }
        if plugin:
            entry["plugin"] = plugin
        if cve:
            entry["cve"] = cve
        self._write(entry)

    def plugin_error(self, plugin_name, port, error):
        entry = {
            "event":     "plugin_error",
            "timestamp": datetime.now().isoformat(),
            "plugin":    plugin_name,
            "port":      port,
            "error":     str(error),
        }
        self._write(entry)
        if self.verbose:
            print(f"[LOG] Plugin error: {plugin_name} on port {port}: {error}")

    def host_discovered(self, ip, method):
        entry = {
            "event":     "host_discovered",
            "timestamp": datetime.now().isoformat(),
            "ip":        ip,
            "method":    method,
        }
        self._write(entry)

    def error(self, message, exc=None):
        entry = {
            "event":     "error",
            "timestamp": datetime.now().isoformat(),
            "message":   message,
        }
        if exc:
            entry["exception"] = str(exc)
        self._write(entry)

    def info(self, message):
        entry = {
            "event":     "info",
            "timestamp": datetime.now().isoformat(),
            "message":   message,
        }
        self._write(entry)


def tail_log(n=50, log_file=None):
    """Print the last n log entries in human-readable format."""
    path = log_file or LOG_FILE
    if not os.path.exists(path):
        print(f"[!] No log file found at {path}")
        return

    with open(path, "r") as f:
        lines = f.readlines()

    recent = lines[-n:]
    print(f"\n{'─'*60}")
    print(f"  BlackPort Log — last {len(recent)} entries")
    print(f"  {path}")
    print(f"{'─'*60}\n")

    for line in recent:
        try:
            entry = json.loads(line.strip())
            ts    = entry.get("timestamp", "")[:19]
            event = entry.get("event", "")

            if event == "scan_start":
                print(f"  {ts}  START   {entry.get('target')} | mode={entry.get('mode')} threads={entry.get('threads')}")
            elif event == "scan_complete":
                print(f"  {ts}  DONE    {entry.get('target')} | {entry.get('open_ports')} ports | score={entry.get('score')}/10 | {entry.get('duration_s')}s")
            elif event == "finding":
                print(f"  {ts}  FINDING {entry.get('target')}:{entry.get('port')} {entry.get('service')} [{entry.get('risk')}]")
            elif event == "plugin_error":
                print(f"  {ts}  ERROR   {entry.get('plugin')} port={entry.get('port')}: {entry.get('error')}")
            elif event == "host_discovered":
                print(f"  {ts}  HOST    {entry.get('ip')} ({entry.get('method')})")
            elif event == "error":
                print(f"  {ts}  ERROR   {entry.get('message')}")
            elif event == "info":
                print(f"  {ts}  INFO    {entry.get('message')}")
        except Exception:
            print(f"  {line.strip()}")

    print()

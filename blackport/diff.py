# =====================================================================
# File: blackport/diff.py
# Notes:
# - This file is part of the BlackPort project.
# - Compares two BlackPort JSON scan results and reports changes.
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import json
import os
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

RISK_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def load_scan(filepath):
    """Load a BlackPort JSON scan result."""
    with open(filepath, "r") as f:
        return json.load(f)


def _normalise(data):
    """
    Normalise a BlackPort scan file into a consistent dict format.
    Handles:
      - List format:   [{port: ..., risk: ...}, ...]
      - New format:    {"target": ..., "results": [...]}
      - Dict of dicts: {port_num: {port: ..., risk: ...}, ...}
    """
    if isinstance(data, list):
        # Port results don't carry a target field — caller can patch after
        return {"target": "unknown", "timestamp": "", "results": data}
    elif isinstance(data, dict):
        if "results" in data:
            return data
        results = list(data.values())
        target = results[0].get("target", "unknown") if results else "unknown"
        return {"target": target, "timestamp": "", "results": results}
    return {"target": "unknown", "timestamp": "", "results": []}


def _port_key(result):
    """Unique key for a port entry."""
    return f"{result['port']}/{result.get('protocol', 'tcp')}"


def _risk_delta(old_risk, new_risk):
    """Return 'escalated', 'improved', or 'unchanged'."""
    old_val = RISK_ORDER.get(old_risk, 0)
    new_val = RISK_ORDER.get(new_risk, 0)
    if new_val > old_val:
        return "escalated"
    elif new_val < old_val:
        return "improved"
    return "unchanged"


def _risk_color(risk):
    colors = {
        "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
        "HIGH":     Fore.RED,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.GREEN,
    }
    return colors.get(risk, "")


def _target_from_filename(filepath):
    """Extract target IP from a BlackPort filename like blackport_192.168.56.104_20260221.json"""
    import re
    base = os.path.basename(filepath)
    match = re.search(r'blackport_(\d+\.\d+\.\d+\.\d+)', base)
    return match.group(1) if match else "unknown"


def compare_scans(old_data, new_data, old_file="", new_file=""):
    """
    Compare two scan result dicts.
    Returns a delta dict with:
      - new_ports:     ports that appeared in new scan
      - closed_ports:  ports that disappeared
      - risk_changes:  ports whose risk level changed
      - unchanged:     ports with no change
      - summary:       high-level stats
    """
    old_data = _normalise(old_data)
    new_data = _normalise(new_data)

    # Patch target from filename if not embedded in data
    if old_data["target"] == "unknown" and old_file:
        old_data["target"] = _target_from_filename(old_file)
    if new_data["target"] == "unknown" and new_file:
        new_data["target"] = _target_from_filename(new_file)

    old_results = old_data.get("results", [])
    new_results = new_data.get("results", [])

    old_map = {_port_key(r): r for r in old_results}
    new_map = {_port_key(r): r for r in new_results}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    delta = {
        "new_ports":    [],
        "closed_ports": [],
        "risk_changes": [],
        "unchanged":    [],
        "summary": {
            "old_target":     old_data.get("target", "unknown"),
            "new_target":     new_data.get("target", "unknown"),
            "old_scan_time":  old_data.get("timestamp", ""),
            "new_scan_time":  new_data.get("timestamp", ""),
            "old_port_count": len(old_keys),
            "new_port_count": len(new_keys),
            "new_open":       0,
            "newly_closed":   0,
            "risk_escalated": 0,
            "risk_improved":  0,
        }
    }

    for key in new_keys - old_keys:
        delta["new_ports"].append(new_map[key])
        delta["summary"]["new_open"] += 1

    for key in old_keys - new_keys:
        delta["closed_ports"].append(old_map[key])
        delta["summary"]["newly_closed"] += 1

    for key in old_keys & new_keys:
        old_r = old_map[key]
        new_r = new_map[key]
        changes = {}

        old_risk = old_r.get("risk", "LOW")
        new_risk = new_r.get("risk", "LOW")
        direction = _risk_delta(old_risk, new_risk)

        if direction != "unchanged":
            changes["risk"] = {"old": old_risk, "new": new_risk, "direction": direction}
            if direction == "escalated":
                delta["summary"]["risk_escalated"] += 1
            else:
                delta["summary"]["risk_improved"] += 1

        old_plugins = {p.get("plugin", "") for p in old_r.get("plugins", []) if p}
        new_plugins = {p.get("plugin", "") for p in new_r.get("plugins", []) if p}
        added = new_plugins - old_plugins
        if added:
            changes["new_plugins"] = list(added)

        if old_r.get("service") != new_r.get("service"):
            changes["service"] = {"old": old_r.get("service"), "new": new_r.get("service")}
        if old_r.get("product") != new_r.get("product"):
            changes["product"] = {"old": old_r.get("product"), "new": new_r.get("product")}
        if old_r.get("version") != new_r.get("version"):
            changes["version"] = {"old": old_r.get("version"), "new": new_r.get("version")}

        if changes:
            delta["risk_changes"].append({"port": new_r, "changes": changes})
        else:
            delta["unchanged"].append(new_r)

    return delta


def print_diff(delta, old_file, new_file):
    """Print a human-readable diff report to terminal."""
    sep = "─" * 60
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  BLACKPORT SCAN DIFF{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"  Old: {os.path.basename(old_file)}")
    print(f"  New: {os.path.basename(new_file)}")
    print(f"  Target: {delta['summary']['new_target']}")
    print(f"{Fore.CYAN}{sep}{Style.RESET_ALL}\n")

    s = delta["summary"]
    print(f"  Ports: {s['old_port_count']} -> {s['new_port_count']}  "
          f"({Fore.GREEN}+{s['new_open']} new{Style.RESET_ALL}, "
          f"{Fore.RED}-{s['newly_closed']} closed{Style.RESET_ALL})")
    print(f"  Risk escalations: {Fore.RED}{s['risk_escalated']}{Style.RESET_ALL}  "
          f"Improvements: {Fore.GREEN}{s['risk_improved']}{Style.RESET_ALL}\n")

    if delta["new_ports"]:
        print(f"{Fore.RED}[NEW PORTS OPENED]{Style.RESET_ALL}")
        for r in sorted(delta["new_ports"], key=lambda x: x.get("port", 0)):
            risk = r.get("risk", "LOW")
            print(f"  + {r['port']}/tcp  {r.get('service','Unknown'):<14} "
                  f"{_risk_color(risk)}{risk}{Style.RESET_ALL}")
        print()

    if delta["closed_ports"]:
        print(f"{Fore.GREEN}[PORTS CLOSED]{Style.RESET_ALL}")
        for r in sorted(delta["closed_ports"], key=lambda x: x.get("port", 0)):
            risk = r.get("risk", "LOW")
            print(f"  - {r['port']}/tcp  {r.get('service','Unknown'):<14} "
                  f"{_risk_color(risk)}{risk}{Style.RESET_ALL}")
        print()

    if delta["risk_changes"]:
        print(f"{Fore.YELLOW}[RISK CHANGES]{Style.RESET_ALL}")
        for entry in delta["risk_changes"]:
            r = entry["port"]
            changes = entry["changes"]
            port_str = f"{r['port']}/tcp {r.get('service','Unknown'):<12}"
            if "risk" in changes:
                old_r = changes["risk"]["old"]
                new_r = changes["risk"]["new"]
                direction = changes["risk"]["direction"]
                arrow = "^ " if direction == "escalated" else "v "
                print(f"  {arrow}{port_str}  "
                      f"{_risk_color(old_r)}{old_r}{Style.RESET_ALL} -> "
                      f"{_risk_color(new_r)}{new_r}{Style.RESET_ALL}")
            if "new_plugins" in changes:
                for p in changes["new_plugins"]:
                    print(f"      New finding: {p}")
            if "version" in changes:
                vc = changes["version"]
                print(f"      Version: {vc['old']} -> {vc['new']}")
        print()

    if not any([delta["new_ports"], delta["closed_ports"], delta["risk_changes"]]):
        print(f"{Fore.GREEN}  No significant changes detected between scans.{Style.RESET_ALL}\n")

    print(f"{Fore.CYAN}{sep}{Style.RESET_ALL}\n")


def save_diff_report(delta, old_file, new_file, output_dir="."):
    """Save the diff as a JSON file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target    = delta["summary"]["new_target"].replace(".", "_")
    filename  = os.path.join(output_dir, f"blackport_diff_{target}_{timestamp}.json")
    report = {
        "type":      "diff",
        "old_scan":  old_file,
        "new_scan":  new_file,
        "generated": datetime.now().isoformat(),
        "summary":   delta["summary"],
        "new_ports":    [r.get("port") for r in delta["new_ports"]],
        "closed_ports": [r.get("port") for r in delta["closed_ports"]],
        "risk_changes": [
            {"port": e["port"].get("port"), "service": e["port"].get("service"), "changes": e["changes"]}
            for e in delta["risk_changes"]
        ],
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[*] Diff report saved: {filename}")
    return filename

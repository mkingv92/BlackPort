"""
MayheM-Sec Added

Post-process BlackPort JSON reports with MayheM-Sec threat intelligence,
confidence scoring, TLS posture, passive web-technology hints, and risk
prioritization. The original upstream fields are preserved and new data is
stored under mayhem_sec.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from blackport.risk_engine_v2 import risk_score
from blackport.threat_intel import enrich_many
from blackport.tls_analysis import analyze_tls
from blackport.web_analysis import analyze_web


def _collect_cves(result: dict) -> list[str]:
    cves: list[str] = []
    info = result.get("cve_info")
    if isinstance(info, dict):
        cve = info.get("cve") or info.get("id")
        if cve:
            cves.append(str(cve))

    for item in result.get("cve_matches") or []:
        if isinstance(item, dict):
            cve = item.get("cve") or item.get("id")
            if cve:
                cves.append(str(cve))
        elif isinstance(item, str) and item.upper().startswith("CVE-"):
            cves.append(item)

    return sorted({c.upper().strip() for c in cves if c})


def enrich_report(path: Path) -> Path:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, list):
        raise ValueError("Expected a BlackPort single-host JSON report containing a list")

    all_cves: list[str] = []
    per_result: list[list[str]] = []
    for result in payload:
        ids = _collect_cves(result) if isinstance(result, dict) else []
        per_result.append(ids)
        all_cves.extend(ids)

    intel = enrich_many(all_cves) if all_cves else {}

    enriched = []
    for result, cves in zip(payload, per_result):
        if not isinstance(result, dict):
            enriched.append(result)
            continue

        result_intel = [intel[cve] for cve in cves if cve in intel]
        mayhem = {
            "cves": cves,
            "intelligence": result_intel,
            "tls": analyze_tls(result.get("tls")),
            "web": analyze_web(result),
        }
        mayhem["risk"] = risk_score(result, result_intel)
        enriched.append({**result, "mayhem_sec": mayhem})

    # MayheM-Sec Added: write a sidecar so upstream JSON remains untouched.
    output = path.with_name(path.stem + ".mayhem.json")
    with output.open("w", encoding="utf-8") as handle:
        json.dump(enriched, handle, indent=2)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Enrich a BlackPort JSON report with MayheM-Sec intelligence")
    parser.add_argument("report", type=Path)
    args = parser.parse_args()

    output = enrich_report(args.report.expanduser().resolve())
    print(f"[MayheM-Sec Added] Enriched report: {output}")


if __name__ == "__main__":
    main()

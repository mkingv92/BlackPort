"""
MayheM-Sec Added

Local report indexing helpers for the BlackPort GUI.

The index reads only files in the configured local reports directory and
returns compact summaries suitable for the dashboard. When an enriched
MayheM-Sec sidecar exists, it is preferred over the matching upstream JSON so
the GUI shows one scan entry instead of duplicate raw/enriched entries.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


REPORT_NAME_RE = re.compile(r"^blackport_(.+?)_(\d{8}_\d{6})(?:\.mayhem)?\.json$")


def _risk_counts(results: list[dict]) -> dict[str, int]:
    """MayheM-Sec Added: prefer fork-specific severity when enrichment exists."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in results:
        mayhem = item.get("mayhem_sec") or {}
        mayhem_risk = str((mayhem.get("risk") or {}).get("severity") or "").upper()
        upstream_risk = str(item.get("risk", "")).upper()
        chosen = mayhem_risk if mayhem_risk in counts else upstream_risk
        if chosen in counts:
            counts[chosen] += 1
    return counts


def _target_from_filename(path: Path) -> str | None:
    match = REPORT_NAME_RE.match(path.name)
    if not match:
        return None
    return match.group(1)


def _report_key(path: Path) -> str:
    """MayheM-Sec Added: normalize raw and .mayhem sidecars to one scan key."""
    name = path.name
    if name.endswith(".mayhem.json"):
        return name[:-12] + ".json"
    return name


def summarize_report(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

    stat = path.stat()
    summary = {
        "name": path.name,
        "path": str(path),
        "modified": stat.st_mtime,
        "protocol": "tcp",
        "target": _target_from_filename(path),
        "findings": 0,
        "open": 0,
        "open_filtered": 0,
        "risk": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "enriched": path.name.endswith(".mayhem.json"),
    }

    if isinstance(payload, dict) and payload.get("protocol") == "udp":
        results = payload.get("results") or []
        summary["protocol"] = "udp"
        summary["target"] = payload.get("target") or summary["target"]
        summary["findings"] = len(results)
        summary["open"] = sum(1 for r in results if r.get("state") == "open")
        summary["open_filtered"] = sum(1 for r in results if r.get("state") == "open|filtered")
        return summary

    if isinstance(payload, list):
        results = [r for r in payload if isinstance(r, dict)]
        summary["findings"] = len(results)
        summary["open"] = len(results)
        summary["risk"] = _risk_counts(results)
        if results and results[0].get("target"):
            summary["target"] = results[0].get("target")
        return summary

    return None


def list_reports(report_dir: Path, limit: int = 50) -> list[dict]:
    if not report_dir.exists():
        return []

    # MayheM-Sec Added: keep one history item per scan and prefer enriched sidecars.
    selected: dict[str, Path] = {}
    for path in report_dir.glob("*.json"):
        key = _report_key(path)
        current = selected.get(key)
        if current is None:
            selected[key] = path
            continue
        if path.name.endswith(".mayhem.json") and not current.name.endswith(".mayhem.json"):
            selected[key] = path
        elif path.stat().st_mtime > current.stat().st_mtime and (
            path.name.endswith(".mayhem.json") == current.name.endswith(".mayhem.json")
        ):
            selected[key] = path

    items = []
    for path in selected.values():
        summary = summarize_report(path)
        if summary:
            items.append(summary)
    items.sort(key=lambda item: item["modified"], reverse=True)
    return items[: max(1, min(limit, 200))]


def load_report(report_dir: Path, name: str) -> dict | list:
    """MayheM-Sec Added: safely load one report by basename only."""
    candidate = (report_dir / Path(name).name).resolve()
    base = report_dir.resolve()
    if candidate.parent != base or not candidate.exists() or candidate.suffix.lower() != ".json":
        raise FileNotFoundError("Report not found")
    return json.loads(candidate.read_text(encoding="utf-8"))

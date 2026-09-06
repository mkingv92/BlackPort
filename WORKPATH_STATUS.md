# BlackPort MayheM-Sec Work Path Status

This checkpoint documents the current MayheM-Sec work branch so development can resume without reconstructing prior decisions.

## Active branch

`mayhem-sec/workpath`

At this checkpoint the branch is ahead of `main` and is intentionally being kept separate until the final validation pass is complete.

## Working decisions

- Preserve original BlackPort upstream attribution.
- Mark fork-specific additions and modifications as **MayheM-Sec Added** where practical.
- Keep the README professional, concise, technical, and human-written in tone.
- Keep the GUI local-only by default on `127.0.0.1`.
- Closing BlackPort must stop active scan child processes and release the localhost listener.
- Use the GUI as a first-class interface, not a separate scanner implementation.
- Prefer polished report cards over raw JSON as the primary GUI report experience.
- Keep raw JSON/HTML/PDF outputs as secondary exports and compatibility artifacts.
- Do not run the final test pass until the feature work path reaches a deliberate validation checkpoint.

## Current MayheM-Sec additions

### GUI

- Local browser GUI.
- TCP, SYN, UDP, and Mixed scan modes.
- Safe, Verify, and Aggressive assessment profiles.
- TCP and UDP scan presets.
- UDP timeout and retry controls.
- Live scan output.
- Stop and full application shutdown controls.
- Process-group cleanup for active scan trees.
- Local scan history.
- Report-history de-duplication that prefers enriched `.mayhem.json` reports.
- Polished TCP and UDP report cards.
- Severity/state filtering.

### UDP

- Dedicated UDP scanner.
- Top 25, Top 50, Top 100, and full-range profiles.
- Conservative `open`, `closed`, and `open|filtered` classification.
- Retry and timeout controls.
- Protocol-aware probes for DNS, NTP, SSDP/UPnP, mDNS, LLMNR, and Memcached.
- Persistent UDP JSON reports.

### Assessment policy

- Safe profile: discovery/fingerprinting with verification plugins disabled.
- Verify profile: reviewed non-destructive verification checks only.
- Aggressive profile: upstream active verification behavior.

### Intelligence and prioritization

- CISA KEV correlation.
- FIRST EPSS lookup with local caching.
- Separate MayheM-Sec confidence scoring.
- Separate MayheM-Sec 0-10 risk scoring while preserving upstream risk fields.
- `.mayhem.json` sidecar enrichment without modifying upstream JSON.
- TLS posture interpretation.
- Passive web-technology hints from already collected data.

### Documentation and development hygiene

- Professional MayheM-Sec fork README.
- `CHANGELOG_MAYHEM.md` for fork-specific history.
- Unit-test scaffold in `tests/test_mayhem_features.py`.
- GitHub Actions MayheM-Sec test workflow scaffold.

## Intentionally not validated yet

The final test pass has **not** been run yet. Treat this branch as development work, not a release.

Items requiring end-of-path validation include:

- GUI startup on supported operating systems.
- localhost-only binding and port release on shutdown.
- process-tree cleanup when scans are stopped or the GUI closes.
- TCP/SYN compatibility with the upstream scanner.
- Safe / Verify / Aggressive policy enforcement.
- UDP classification accuracy and retry behavior.
- mixed-mode orchestration.
- report persistence and history indexing.
- `.mayhem.json` enrichment.
- KEV/EPSS cache and offline fallback behavior.
- TLS/web enrichment rendering.
- polished report-card rendering and filtering.
- Windows/Linux/macOS differences where applicable.

## Known limitations

- UDP and Mixed modes currently accept a single IP address or hostname; UDP CIDR orchestration is not enabled yet.
- UDP silence is intentionally reported as `open|filtered`, not confirmed open.
- Full UDP scans can be significantly slower than curated profiles.
- Legacy GUI implementation files (`gui_server_v2.py`, `gui_server_v3.py`) remain in the work branch as development layers; the active path is `gui.py` -> `gui_server_v4.py`. They should be reviewed for cleanup after validation rather than deleted blindly before testing.

## Recommended resume order

1. Inspect current branch diff against `main` and confirm no unexpected upstream changes need syncing.
2. Review the active GUI path (`gui.py` -> `gui_server_v4.py`) and decide whether legacy v2/v3 modules should remain as internal dependencies or be flattened after tests.
3. Run static/import tests before any live network tests.
4. Run unit tests in `tests/test_mayhem_features.py`.
5. Test GUI lifecycle locally: start, scan, stop, shutdown, port release.
6. Test TCP/SYN against an authorized lab target.
7. Test UDP Top 25/50/100 against controlled services with known open/closed ports.
8. Test Mixed mode and verify both TCP and UDP reports persist.
9. Test Safe / Verify / Aggressive policy boundaries.
10. Verify report cards, history de-duplication, KEV/EPSS, TLS, and web enrichment.
11. Fix issues found during validation.
12. Only after validation, clean legacy development files, update release notes/versioning, and decide whether to merge the work branch into `main` or open focused upstream pull requests.

## Safe stopping point

No further feature additions are required before resuming. The next session should begin with validation and consolidation rather than adding another major subsystem.

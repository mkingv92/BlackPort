# MayheM-Sec BlackPort Changelog

This file tracks changes introduced by the MayheM-Sec fork. It does not replace upstream BlackPort history or attribution.

## Unreleased

### Added

- **MayheM-Sec Added:** local browser-based BlackPort GUI bound to `127.0.0.1` by default.
- **MayheM-Sec Added:** GUI start, stop, and application shutdown controls.
- **MayheM-Sec Added:** process-group cleanup so closing the GUI also terminates active scan children.
- **MayheM-Sec Added:** explicit Safe, Verify, and Aggressive assessment profiles.
- **MayheM-Sec Added:** GUI scan history and polished local report cards rather than raw JSON as the primary viewing experience.
- **MayheM-Sec Added:** TCP finding cards with service, product/version, severity, risk score, confidence, CVEs, KEV/EPSS intelligence, TLS posture, passive web-technology hints, and collected evidence where available.
- **MayheM-Sec Added:** UDP finding cards with state, confidence, probe type, retries, latency, response size, and response evidence where available.
- **MayheM-Sec Added:** report filters for TCP severities and UDP states.
- **MayheM-Sec Added:** report-history de-duplication that prefers `.mayhem.json` enriched sidecars when both raw and enriched versions exist.
- **MayheM-Sec Added:** dedicated UDP scanner with conservative UDP state handling.
- **MayheM-Sec Added:** UDP Top 25, Top 50, Top 100, and full-range profiles.
- **MayheM-Sec Added:** protocol-aware UDP probes for DNS, NTP, SSDP/UPnP, mDNS, LLMNR, and Memcached.
- **MayheM-Sec Added:** UDP JSON report persistence.
- **MayheM-Sec Added:** unified `mayhem_scan.py` launcher for TCP, SYN, UDP, and mixed modes.
- **MayheM-Sec Added:** CISA KEV and FIRST EPSS enrichment with local caching.
- **MayheM-Sec Added:** confidence and second-generation MayheM-Sec risk scoring while preserving upstream risk fields.
- **MayheM-Sec Added:** enriched `.mayhem.json` sidecar reports so upstream JSON remains unchanged.
- **MayheM-Sec Added:** TLS posture analysis for expiry, hostname mismatch, self-signed certificates, weak ciphers, and legacy protocol support.
- **MayheM-Sec Added:** passive web-technology hints derived from data BlackPort already collects.

### Changed

- **MayheM-Sec Added:** replaced the legacy `FastScan Pro` Tkinter launcher with a compatibility entry point for the local BlackPort browser interface.
- **MayheM-Sec Added:** `gui.py` and `gui_server.py` now route to the current v4 local interface.
- **MayheM-Sec Added:** rewrote the fork README to clearly separate upstream functionality from MayheM-Sec additions and remove overly promotional wording.
- **MayheM-Sec Added:** fork-specific orchestration keeps upstream TCP/SYN behavior in `main.py` rather than duplicating the original scanner.
- **MayheM-Sec Added:** report-history risk counts prefer MayheM-Sec enriched severity when enrichment is present.
- **MayheM-Sec Added:** added the missing `packaging` runtime dependency required by the existing upstream `exploit_indicators.py` import.

### Validation

The MayheM-Sec work path completed its automated end-to-end validation on GitHub Actions. The successful run covered:

- dependency installation
- Python compile checks for MayheM-Sec modules
- eight fork-specific unit tests
- CLI entry-point help checks
- localhost UDP smoke scanning and report creation
- localhost Safe TCP smoke scanning
- local GUI startup, status endpoint, shutdown endpoint, and clean process exit

### Known limitations

- UDP and mixed modes currently target a single IP address or hostname; UDP CIDR orchestration is not enabled yet.
- UDP silence is intentionally classified as `open|filtered`, not as a confirmed open port.
- Full UDP scans are expected to take substantially longer than curated UDP profiles.
- SYN behavior still depends on platform raw-socket privileges and should receive a real authorized target test before a release is tagged.
- Aggressive profile behavior intentionally preserves upstream active verification and should only be used within an explicitly authorized assessment scope.

## Attribution

Original BlackPort work remains attributed to Matthew Valdez (`mkingv92`). Only fork-specific additions or modifications are labeled **MayheM-Sec Added**.

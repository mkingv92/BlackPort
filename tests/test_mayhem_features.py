"""
MayheM-Sec Added

Unit-test coverage for fork-specific BlackPort features.
These tests are intentionally lightweight and avoid scanning external systems.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from blackport.risk_engine_v2 import confidence_score, risk_score
from blackport.tls_analysis import analyze_tls
from udp_scanner import TOP_25_UDP, TOP_50_UDP, TOP_100_UDP, UDPScanner, write_json_report


class UDPProfileTests(unittest.TestCase):
    def test_udp_profiles_expand(self):
        self.assertLessEqual(set(TOP_25_UDP), set(TOP_50_UDP))
        self.assertLessEqual(set(TOP_50_UDP), set(TOP_100_UDP))

    def test_udp_profiles_have_valid_ports(self):
        for profile in (TOP_25_UDP, TOP_50_UDP, TOP_100_UDP):
            self.assertTrue(profile)
            self.assertTrue(all(1 <= port <= 65535 for port in profile))

    def test_udp_unknown_port_uses_generic_probe(self):
        scanner = UDPScanner("127.0.0.1", timeout=0.1, retries=1, workers=1)
        self.assertEqual(scanner._probe_payload(65534), b"\x00")

    def test_udp_report_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_json_report(
                "127.0.0.1",
                0.1,
                [{"port": 53, "protocol": "udp", "state": "open"}],
                directory,
            )
            self.assertTrue(path.exists())
            self.assertTrue(path.name.endswith("_udp.json"))


class RiskEngineTests(unittest.TestCase):
    def test_confidence_increases_with_evidence(self):
        bare = {"service": "Unknown", "risk": "LOW"}
        rich = {
            "service": "HTTPS",
            "banner": "nginx",
            "product": "nginx",
            "version": "1.24",
            "confidence": 90,
            "risk": "HIGH",
            "plugins": [{"risk": "HIGH"}],
        }
        self.assertGreater(confidence_score(rich), confidence_score(bare))

    def test_kev_and_epss_raise_priority(self):
        result = {"service": "HTTP", "risk": "HIGH", "confidence": 90}
        baseline = risk_score(result, [])
        enriched = risk_score(result, [{
            "cisa_kev": True,
            "epss": {"epss": 0.95, "percentile": 0.99},
        }])
        self.assertGreaterEqual(enriched["score"], baseline["score"])
        self.assertTrue(enriched["cisa_kev"])


class TLSAnalysisTests(unittest.TestCase):
    def test_legacy_tls_is_reported(self):
        result = analyze_tls({
            "certificate": {},
            "supported_tls_versions": ["TLSv1", "TLSv1_2", "TLSv1_3"],
            "flags": {"weak_protocols": True, "downgrade_risk": True},
        })
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("TLS_LEGACY_PROTOCOL", codes)
        self.assertIn("TLS_DOWNGRADE_SURFACE", codes)

    def test_no_tls_returns_none(self):
        self.assertIsNone(analyze_tls(None))


if __name__ == "__main__":
    unittest.main()

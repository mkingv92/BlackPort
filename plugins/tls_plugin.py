# plugins/tls_plugin.py
from .plugin_base import PluginBase
from tls_enum import get_tls_details

class TLSPlugin(PluginBase):
    name = "TLS Intelligence"
    applicable_services = ["HTTPS"]

    def run(self, target, port, banner=None):
        tls_info = get_tls_details(target, port, server_name=target)
        if not tls_info:
            return {
                "plugin": self.name,
                "risk": "LOW",
                "notes": "No TLS information retrieved."
            }

        weak_ciphers = [c for c in tls_info.get("ciphers", []) if c in ["DES", "3DES", "RC4", "MD5"]]
        risk = "LOW"
        notes = f"TLS {tls_info.get('protocol', 'unknown')} detected."

        if weak_ciphers:
            risk = "HIGH"
            notes += f" Weak ciphers detected: {', '.join(weak_ciphers)}"

        if tls_info.get("expired_cert"):
            risk = "HIGH"
            notes += " Certificate is expired or invalid."

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": notes,
            "exploit_hint": None
        }

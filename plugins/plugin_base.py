# plugins/plugin_base.py
class PluginBase:
    name = "Base Plugin"
    applicable_services = []  # e.g. ["HTTP", "SMB"]

    def run(self, target, port, banner=None):
        """
        Must return a dict with:
        {
            "plugin": self.name,
            "risk": "LOW" / "MEDIUM" / "HIGH" / "CRITICAL",
            "notes": "Human-readable description",
            "exploit_hint": Optional exploit hint
        }
        """
        raise NotImplementedError

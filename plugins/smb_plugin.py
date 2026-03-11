# plugins/smb_plugin.py
from .plugin_base import PluginBase
from enum_modules import enum_smb_shares

class SMBPlugin(PluginBase):
    name = "SMB Misconfiguration"
    applicable_services = ["SMB"]

    def run(self, target, port, banner=None):
        smb_info = enum_smb_shares(target)

        if not smb_info:
            return {
                "plugin": self.name,
                "risk": "LOW",
                "notes": "Could not enumerate SMB shares."
            }

        version = smb_info.get("version")
        signing = smb_info.get("signing")

        if version == "SMBv1":
            risk = "CRITICAL"
            notes = "Legacy SMBv1 detected, highly vulnerable."
        elif version in ["SMBv2", "SMBv3"] and signing is False:
            risk = "HIGH"
            notes = "Modern SMB without signing enabled."
        elif version in ["SMBv2", "SMBv3"] and signing is True:
            risk = "MEDIUM"
            notes = "Modern SMB with signing enabled."
        else:
            risk = "LOW"
            notes = "Unknown SMB version."

        return {
            "plugin": self.name,
            "risk": risk,
            "notes": notes,
            "exploit_hint": "EternalBlue exploit possible" if version == "SMBv1" else None
        }

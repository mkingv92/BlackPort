# =====================================================================
# File: fingerprint_engine.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import re

FINGERPRINTS = [
    {
        "service": "FTP",
        "product": "vsFTPd",
        "pattern": r"vsFTPd\s+([\d\.]+)",
        "confidence": 95
    },
    {
        "service": "SSH",
        "product": "OpenSSH",
        "pattern": r"OpenSSH[_\s]([\d\.p]+)",
        "confidence": 95
    },
    {
        "service": "HTTP",
        "product": "Apache",
        "pattern": r"Apache/?([\d\.]+)?",
        "confidence": 90
    },
    {
        "service": "HTTP",
        "product": "nginx",
        "pattern": r"nginx/?([\d\.]+)?",
        "confidence": 90
    },
    {
        "service": "HTTP",
        "product": "Microsoft-IIS",
        "pattern": r"Microsoft-IIS/?([\d\.]+)?",
        "confidence": 90
    }
]

# NOTE: fingerprint_service() - helper/entry function. Read the body for the exact steps.
def fingerprint_service(port, banner):
        if not banner:
            return None, None, None, 0

        for fp in FINGERPRINTS:
            match = re.search(fp["pattern"], banner, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else None
                return (
                    fp["service"],
                    fp["product"],
                    version,
                    fp["confidence"]
                )

        return None, None, None, 10  # Low confidence fallback

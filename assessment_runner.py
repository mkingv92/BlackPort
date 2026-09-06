"""
MayheM-Sec Added

Assessment policy wrapper for the upstream BlackPort TCP/SYN scanner.

Profiles:
- safe: no verification plugins and no SMB post-sweep enumeration
- verify: only explicitly reviewed non-destructive verification plugins
- aggressive: preserve the upstream BlackPort plugin behavior

The upstream scanner code is not relabeled or rewritten. This module changes
which existing plugin objects are made available for a single scan process.
"""

from __future__ import annotations

import argparse
import sys

import blackport.scanner as scanner_module


# MayheM-Sec Added: conservative allowlist; expand only after plugin review.
VERIFY_PLUGIN_CLASSES = {
    "ApachePlugin",
    "SSHPlugin",
}


def apply_profile(profile: str) -> dict:
    """MayheM-Sec Added: apply one policy to the scanner module for this process."""
    original_plugins = list(scanner_module.plugins)

    if profile == "safe":
        scanner_module.plugins = []
        # Safe mode avoids the separate SMB enumeration phase as well.
        scanner_module.SMB_PORTS = set()
    elif profile == "verify":
        scanner_module.plugins = [
            plugin for plugin in original_plugins
            if plugin.__class__.__name__ in VERIFY_PLUGIN_CLASSES
        ]
    elif profile == "aggressive":
        scanner_module.plugins = original_plugins
    else:
        raise ValueError(f"Unknown assessment profile: {profile}")

    return {
        "profile": profile,
        "plugins_enabled": [plugin.__class__.__name__ for plugin in scanner_module.plugins],
        "plugin_count": len(scanner_module.plugins),
        "smb_post_sweep": bool(scanner_module.SMB_PORTS),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BlackPort assessment policy wrapper - MayheM-Sec Added",
        add_help=True,
    )
    parser.add_argument("--profile", choices=["safe", "verify", "aggressive"], default="safe")
    parser.add_argument("scanner_args", nargs=argparse.REMAINDER, help="Arguments passed to main.py")
    args = parser.parse_args()

    scanner_args = list(args.scanner_args)
    if scanner_args and scanner_args[0] == "--":
        scanner_args = scanner_args[1:]
    if not scanner_args:
        parser.error("Provide the normal BlackPort target and scan arguments after --profile")

    status = apply_profile(args.profile)
    print(
        f"[MayheM-Sec Added] Assessment profile: {status['profile'].upper()} | "
        f"plugins={status['plugin_count']} | SMB post-sweep={'on' if status['smb_post_sweep'] else 'off'}"
    )

    # Import after policy application. PortScanner still uses the scanner module
    # globals modified above, while upstream CLI parsing/orchestration remains intact.
    import main as upstream_main

    sys.argv = [str(getattr(upstream_main, "__file__", "main.py"))] + scanner_args
    upstream_main.main()


if __name__ == "__main__":
    main()

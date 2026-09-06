"""
MayheM-Sec Added

Compatibility launcher for the BlackPort local graphical interface.
The MayheM-Sec fork uses gui_server_v4.py for TCP, SYN, UDP, Mixed scans,
Safe/Verify/Aggressive assessment profiles, scan history, and local reports.
"""

from gui_server_v4 import main


if __name__ == "__main__":
    main()

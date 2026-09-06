"""
MayheM-Sec Added

Canonical BlackPort local GUI entry point.

The active interface lives in gui_server_v4.py. This compatibility module keeps
`python gui_server.py` working while the work branch is consolidated for final
testing and release cleanup.
"""

from gui_server_v4 import main


if __name__ == "__main__":
    main()

# =====================================================================
# File: utils.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

import logging

# NOTE: setup_logger() - helper/entry function. Read the body for the exact steps.
def setup_logger():
    logging.basicConfig(
        filename="BlackPort.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

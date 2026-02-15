# =====================================================================
# File: setup.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from setuptools import setup, find_packages

setup(
    name="fastscan-x",
    version="1.0",
    packages=find_packages(),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "fastscan=main:main"
        ]
    },
)

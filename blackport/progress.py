# =====================================================================
# File: progress.py
# Notes:
# - This file is part of the BlackPort project.
# - The comments added here are for readability only (no behavior change).
# - Use only on hosts/networks you own or have explicit permission to test.
# =====================================================================

from tqdm import tqdm


# NOTE: track_progress() - helper/entry function. Read the body for the exact steps.
def track_progress(futures):
    results = []
    for future in tqdm(futures, desc="Scanning", unit="port"):
        results.append(future.result())
    return results

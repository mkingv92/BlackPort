from tqdm import tqdm


def track_progress(futures):
    results = []
    for future in tqdm(futures, desc="Scanning", unit="port"):
        results.append(future.result())
    return results

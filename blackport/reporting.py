import json
from datetime import datetime

def save_json(results, filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)


def save_html(results, filename):
    html = f"""
    <html>
    <body>
    <h2>FastScan X Report</h2>
    <p>Generated: {datetime.now()}</p>
    <table border="1">
    <tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th></tr>
    """

    for r in results:
        html += f"<tr><td>{r['host']}</td><td>{r['port']}</td><td>{r['service']}</td><td>{r['banner']}</td></tr>"

    html += "</table></body></html>"

    with open(filename, "w") as f:
        f.write(html)

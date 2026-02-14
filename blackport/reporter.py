def generate_html_report(target, results, os_guess, risk_level):
    filename = f"{target}_report.html"

    with open(filename, "w") as f:
        f.write(f"""
        <html>
        <head>
        <title>FastScan Pro Report</title>
        </head>
        <body>
        <h1>Scan Report for {target}</h1>
        <h2>Detected OS: {os_guess}</h2>
        <h2>Risk Level: {risk_level}</h2>
        <hr>
        <pre>
        {results}
        </pre>
        </body>
        </html>
        """)

    return filename

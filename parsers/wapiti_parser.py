import json
import os


def parse(report_file):

    issues = []

    if not os.path.exists(report_file):
        return issues

    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", {})

    for vuln_type, items in vulns.items():

        for v in items:
            issues.append({
                "type": vuln_type,
                "url": v.get("path"),
                "parameter": v.get("parameter"),
                "info": v.get("info"),
                "level": v.get("level"),
                "reference": v.get("reference")
            })

    os.remove(report_file)

    return issues
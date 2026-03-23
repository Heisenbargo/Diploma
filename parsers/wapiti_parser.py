import json
import os


def parse(report_file):

    issues = []

    if not os.path.exists(report_file):
        return issues

    try:
        with open(report_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        vulnerabilities = data.get("vulnerabilities", {})

        for vuln_type, vuln_list in vulnerabilities.items():

            for v in vuln_list:

                issues.append({
                    "type": vuln_type,
                    "url": v.get("path"),
                    "parameter": v.get("parameter"),
                    "method": v.get("method"),
                    "info": v.get("info"),
                    "level": v.get("level"),
                    "reference": v.get("reference")
                })

    except Exception as e:
        print("Ошибка парсинга:", e)

    try:
        os.remove(report_file)
    except:
        pass

    return issues
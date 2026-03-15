def parse(output):

    issues = []

    for line in output.splitlines():

        if line.startswith("+"):

            issues.append({
                "port": 80,
                "url": "",
                "issue": line[1:].strip(),
                "description": line[1:].strip(),
                "reference": "",
                "severity": "Medium"
            })

    return issues
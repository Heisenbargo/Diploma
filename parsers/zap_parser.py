def parse(alerts):

    vulns = []

    for a in alerts:

        vulns.append({

            "url": a.get("url"),
            "method": a.get("method"),
            "parameter": a.get("param"),
            "alert": a.get("alert"),
            "description": a.get("description"),
            "attack": a.get("attack"),
            "evidence": a.get("evidence"),
            "risk": a.get("risk"),
            "confidence": a.get("confidence")

        })

    return vulns
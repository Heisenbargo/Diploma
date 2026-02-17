import time
from zapv2 import ZAPv2

def scan(target):
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    zap = ZAPv2(proxies={
        'http': 'http://127.0.0.1:8090',
        'https': 'http://127.0.0.1:8090'
    })

    spider_id = zap.spider.scan(target)
    while zap.spider.status(spider_id) != '100':
        time.sleep(2)

    ascan_id = zap.ascan.scan(target)
    while zap.ascan.status(ascan_id) != '100':
        time.sleep(5)

    alerts = zap.core.alerts(baseurl=target)

    if not alerts:
        return "Уязвимости не обнаружены"

    result = []
    for a in alerts:
        result.append(
            f"[{a['risk']}] {a['alert']}\n"
            f"URL: {a['url']}\n"
            f"Описание: {a['description']}\n"
            f"Решение: {a['solution']}\n"
            "-------------------------"
        )

    return "\n".join(result)

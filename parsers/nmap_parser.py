import re


def parse(output):

    services = []

    pattern = r"(\d+)/tcp\s+(\w+)\s+([\w\-]+)\s*(.*)"

    for line in output.splitlines():

        m = re.search(pattern, line)

        if m:

            services.append({
                "port": int(m.group(1)),
                "protocol": "tcp",
                "state": m.group(2),
                "service": m.group(3),
                "product": "",
                "version": m.group(4),
                "extra_info": ""
            })

    return services
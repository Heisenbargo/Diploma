from utils.runner import run_command

REPORT_FILE = "wapiti_temp.json"


def scan(target, args):

    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    command = [
        "wapiti",
        "-u", target,
        "-f", "json",
        "-o", REPORT_FILE
    ] + args

    output = run_command(command)

    return output, REPORT_FILE
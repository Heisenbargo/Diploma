from utils.runner import run_command


def scan(target: str, args: list) -> str:
    command = ["nmap"] + args + [target]
    return run_command(command)

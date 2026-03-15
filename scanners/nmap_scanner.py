from utils.runner import run_command


def scan(target, args):

    command = ["nmap"] + args + [target]

    return run_command(command)
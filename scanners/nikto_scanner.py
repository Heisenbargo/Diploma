from utils.runner import run_command
import os

NIKTO_PATH = r"D:/Nikto/nikto-master/nikto-master/program/nikto.pl"
NIKTO_DIR = os.path.dirname(NIKTO_PATH)


def scan(target, args=None):

    args = args or []

    command = ["perl", NIKTO_PATH, "-h", target] + args

    return run_command(command, cwd=NIKTO_DIR)
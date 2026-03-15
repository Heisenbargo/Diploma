import subprocess

def run_command(command, cwd=None):

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        cwd=cwd
    )

    return result.stdout + result.stderr
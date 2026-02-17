import subprocess


def run_command(command: list) -> str:
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return process.stdout + process.stderr
    except Exception as e:
        return f"Ошибка запуска: {e}"

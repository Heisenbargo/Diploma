import subprocess

def run_command(command):

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    # если есть нормальный stdout → показываем его
    if result.stdout.strip():
        return result.stdout

    # иначе показываем stderr (но аккуратно)
    return "Ошибка выполнения сканера"
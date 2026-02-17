import os
from utils.runner import run_command

NIKTO_PATH = "D:/Nikto/nikto-master/nikto-master/program/nikto.pl"


def scan(target: str, args: list[str]) -> str:
    """
    Запуск сканирования Nikto

    :param target: URL или IP (обязательно с http/https)
    :param args: список аргументов Nikto (например ["-Tuning x", "-ssl"])
    :return: текст результата сканирования
    """

    if not os.path.exists(NIKTO_PATH):
        return (
            "Ошибка: файл nikto.pl не найден.\n"
            f"Ожидаемый путь:\n{NIKTO_PATH}"
        )

    if not target.startswith(("http://", "https://")):
        return "Ошибка: укажите URL с http:// или https://"

    command = ["perl", NIKTO_PATH, "-h", target]

    for arg in args:
        if isinstance(arg, str):
            command.extend(arg.split())

    try:
        output = run_command(command)

        if not output.strip():
            return "Сканирование завершено, но Nikto не вернул результатов."

        return output

    except Exception as e:
        return f"Ошибка при запуске Nikto: {str(e)}"

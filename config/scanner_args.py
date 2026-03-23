SCANNER_ARGUMENTS = {

    "nmap": {
        "-sS": "TCP SYN scan",
        "-sV": "Service detection",
        "-O": "OS detection"
    },

    "wapiti": {
        "-v 2": "Подробный вывод",
        "--flush-session": "Игнорировать предыдущие сессии",
        "--scope domain": "Сканировать только домен",
        "--timeout 10": "Таймаут запросов",
        "--max-links-per-page 10": "Ограничение ссылок",
    },

    "zap": {}
}
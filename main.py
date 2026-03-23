import tkinter as tk
from tkinter import ttk
import subprocess
import time

from database import *
from config.scanner_args import SCANNER_ARGUMENTS

from scanners.zap_scanner import scan as zap_scan

from parsers.nmap_parser import parse as nmap_parse

from scanners.wapiti_scanner import scan as wapiti_scan
from parsers.wapiti_parser import parse as wapiti_parse


init_db()

SCANNERS = ["nmap", "zap", "wapiti"]


def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout + result.stderr


# ================= FORMATTERS =================

def format_wapiti(issues):

    if not issues:
        return "Уязвимости не обнаружены"

    result = []

    for i in issues:
        result.append(
            f"[{i.get('level')}] {i.get('type')}\n"
            f"URL: {i.get('url')}\n"
            f"Параметр: {i.get('parameter')}\n"
            f"Метод: {i.get('method')}\n"
            f"Описание: {i.get('info')}\n"
            f"Рекомендация: {i.get('reference')}\n"
            "-------------------------"
        )

    return "\n".join(result)


# ================= MAIN LOGIC =================

def run_scan():

    scanner = scanner_var.get()
    arg = arg_var.get()
    target = target_entry.get().strip()

    if not target:
        return

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "Сканирование запущено...\n")
    root.update()

    target_id = get_or_create_target(target)

    scan_args = []
    if scanner != "zap" and arg:
        scan_args.append(arg)

    scan_id = create_scan(target_id, scanner, scan_args)

    output = ""

    try:

        # ========= NMAP =========
        if scanner == "nmap":

            command = ["nmap"] + scan_args + [target]
            raw = run_command(command)

            services = nmap_parse(raw)
            save_services(target_id, services)

            output = raw

        # ========= ZAP =========
        elif scanner == "zap":

            output, vulns = zap_scan(target)
            save_vulnerabilities(target_id, vulns)

        # ========= WAPITI =========
        elif scanner == "wapiti":

            raw, report_file = wapiti_scan(target, scan_args)

            import time
            time.sleep(2)  # дождаться записи файла

            issues = wapiti_parse(report_file)

            save_wapiti_issues(target_id, issues)

            if not issues:
                output = "Уязвимости не обнаружены"
            else:
                output = ""

                for i in issues:
                    output += (
                        f"[{i.get('level')}] {i.get('type')}\n"
                        f"URL: {i.get('url')}\n"
                        f"Параметр: {i.get('parameter')}\n"
                        f"Метод: {i.get('method')}\n"
                        f"Описание: {i.get('info')}\n"
                        f"Решение: {i.get('reference')}\n"
                        "-------------------------\n"
                    )

        finish_scan(scan_id, output)

    except Exception as e:
        output = f"Ошибка:\n{e}"

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, output)


def on_scanner_change(event=None):

    scanner = scanner_var.get()

    if scanner == "zap":
        arg_combo["values"] = []
        arg_var.set("")
        arg_desc_var.set("Для ZAP аргументы не требуются")
        return

    args = list(SCANNER_ARGUMENTS.get(scanner, {}).keys())
    arg_combo["values"] = args

    if args:
        arg_combo.current(0)
        on_argument_change()


def on_argument_change(event=None):

    scanner = scanner_var.get()
    arg = arg_var.get()

    if arg in SCANNER_ARGUMENTS.get(scanner, {}):
        arg_desc_var.set(SCANNER_ARGUMENTS[scanner][arg])


# ================= GUI =================

root = tk.Tk()
root.title("Сканер уязвимостей")
root.geometry("1000x600")

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill="both", expand=True)

left = ttk.Frame(main_frame, width=300)
left.pack(side="left", fill="y")

right = ttk.Frame(main_frame)
right.pack(side="right", fill="both", expand=True)

scanner_var = tk.StringVar(value="nmap")
scanner_combo = ttk.Combobox(left, textvariable=scanner_var, values=SCANNERS, state="readonly")
scanner_combo.pack(fill="x")
scanner_combo.bind("<<ComboboxSelected>>", on_scanner_change)

arg_var = tk.StringVar()
arg_combo = ttk.Combobox(left, textvariable=arg_var)
arg_combo.pack(fill="x")
arg_combo.bind("<<ComboboxSelected>>", on_argument_change)

arg_desc_var = tk.StringVar()
ttk.Label(left, textvariable=arg_desc_var, wraplength=250).pack()

target_entry = ttk.Entry(left)
target_entry.pack(fill="x")

ttk.Button(left, text="Сканировать", command=run_scan).pack()

output_text = tk.Text(right)
output_text.pack(fill="both", expand=True)

on_scanner_change()
root.mainloop()
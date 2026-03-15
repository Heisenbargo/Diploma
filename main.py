import tkinter as tk
from tkinter import ttk
import subprocess

from database import *
from config.scanner_args import SCANNER_ARGS
from scanners.zap_scanner import scan as zap_scan


init_db()

SCANNERS = ["nmap", "nikto", "zap"]


def run_command(command):

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.stdout + result.stderr


def parse_nmap(output):

    services = []

    for line in output.splitlines():

        if "/tcp" in line and "open" in line:

            parts = line.split()

            try:
                services.append({
                    "port": int(parts[0].split("/")[0]),
                    "protocol": "tcp",
                    "state": parts[1],
                    "service": parts[2],
                    "product": "",
                    "version": "",
                    "extra_info": ""
                })
            except:
                pass

    return services


def parse_nikto(output):

    issues = []

    for line in output.splitlines():

        if line.startswith("+"):

            issues.append({
                "port": 80,
                "url": "",
                "issue": line[1:].strip(),
                "description": line[1:].strip(),
                "reference": "",
                "severity": "Medium"
            })

    return issues


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

        if scanner == "nmap":

            command = ["nmap"]

            if arg:
                command.append(arg)

            command.append(target)

            output = run_command(command)

            services = parse_nmap(output)

            save_services(target_id, services)


        elif scanner == "nikto":

            command = ["nikto", "-h", target]

            if arg:
                command.append(arg)

            output = run_command(command)

            issues = parse_nikto(output)

            save_web_issues(scan_id, issues)


        elif scanner == "zap":

            output, vulnerabilities = zap_scan(target)

            save_vulnerabilities(scan_id, vulnerabilities)


        finish_scan(scan_id, output)


    except Exception as e:

        output = f"Ошибка при сканировании:\n{e}"


    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, output)


def on_scanner_change(event=None):

    scanner = scanner_var.get()

    if scanner == "zap":

        arg_combo["values"] = []
        arg_var.set("")
        arg_desc_var.set("Для ZAP аргументы не требуются")
        return

    args = list(SCANNER_ARGS[scanner].keys())

    arg_combo["values"] = args

    if args:
        arg_combo.current(0)
        on_argument_change()


def on_argument_change(event=None):

    scanner = scanner_var.get()
    arg = arg_var.get()

    if scanner == "zap":
        return

    if arg in SCANNER_ARGS[scanner]:
        arg_desc_var.set(SCANNER_ARGS[scanner][arg])


# ================= GUI =================

root = tk.Tk()
root.title("Программа сканирования уязвимостей серверов и сайтов")
root.geometry("1000x600")
root.minsize(900, 550)

style = ttk.Style()
style.theme_use("default")


main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill="both", expand=True)

left_frame = ttk.Frame(main_frame, width=300)
left_frame.pack(side="left", fill="y", padx=(0, 10))

right_frame = ttk.Frame(main_frame)
right_frame.pack(side="right", fill="both", expand=True)


ttk.Label(
    left_frame,
    text="Параметры сканирования",
    font=("Segoe UI", 11, "bold")
).pack(anchor="w", pady=(0, 10))

ttk.Label(left_frame, text="Сканер:").pack(anchor="w")

scanner_var = tk.StringVar(value="nmap")

scanner_combo = ttk.Combobox(
    left_frame,
    textvariable=scanner_var,
    values=SCANNERS,
    state="readonly"
)

scanner_combo.pack(fill="x", pady=5)
scanner_combo.bind("<<ComboboxSelected>>", on_scanner_change)


ttk.Label(left_frame, text="Аргумент:").pack(anchor="w", pady=(10, 0))

arg_var = tk.StringVar()

arg_combo = ttk.Combobox(
    left_frame,
    textvariable=arg_var,
    state="readonly"
)

arg_combo.pack(fill="x", pady=5)
arg_combo.bind("<<ComboboxSelected>>", on_argument_change)


ttk.Label(
    left_frame,
    text="Описание аргумента:",
    font=("Segoe UI", 9, "bold")
).pack(anchor="w", pady=(10, 0))


arg_desc_var = tk.StringVar(value="Выберите аргумент")

arg_desc_label = ttk.Label(
    left_frame,
    textvariable=arg_desc_var,
    wraplength=280,
    foreground="#444"
)

arg_desc_label.pack(anchor="w", pady=5)


ttk.Label(
    left_frame,
    text="IP-адрес или URL:",
    font=("Segoe UI", 9, "bold")
).pack(anchor="w", pady=(15, 0))


target_entry = ttk.Entry(left_frame)
target_entry.pack(fill="x", pady=5)


ttk.Button(
    left_frame,
    text="Запустить сканирование",
    command=run_scan
).pack(fill="x", pady=20)


ttk.Label(
    right_frame,
    text="Результат сканирования",
    font=("Segoe UI", 11, "bold")
).pack(anchor="w")


output_text = tk.Text(
    right_frame,
    wrap="word",
    font=("Consolas", 10)
)

output_text.pack(fill="both", expand=True, pady=5)


scrollbar = ttk.Scrollbar(output_text, command=output_text.yview)
output_text.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side="right", fill="y")


on_scanner_change()

root.mainloop()
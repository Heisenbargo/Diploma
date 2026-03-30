import tkinter as tk
from tkinter import ttk
import subprocess
import time

from database import *
from config.scanner_args import SCANNER_ARGUMENTS

from scanners.zap_scanner import scan as zap_scan
from scanners.wapiti_scanner import scan as wapiti_scan
from parsers.wapiti_parser import parse as wapiti_parse

init_db()

SCANNERS = ["nmap", "zap", "wapiti"]


# ---------------- RUN COMMAND ----------------

def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )
    return result.stdout + result.stderr


# ---------------- NMAP PARSER ----------------

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

# ---------------- ARGUMENT LOGIC ----------------

def on_scanner_change(event=None):

    scanner = scanner_var.get()

    # ZAP — без аргументов
    if scanner == "zap":
        arg_box["values"] = []
        arg_var.set("")
        arg_box.configure(state="disabled")
        return

    # Получаем аргументы
    args = list(SCANNER_ARGUMENTS.get(scanner, {}).keys())

    arg_box.configure(state="normal")
    arg_box["values"] = args

    if args:
        arg_var.set(args[0])
    else:
        arg_var.set("")


def on_argument_change(event=None):
    # можно позже добавить описание аргумента
    pass

# ---------------- RUN SCAN ----------------

def run_scan():

    scanner = scanner_var.get()
    arg = arg_var.get()
    target = target_entry.get().strip()

    if not target:
        return

    raw_text.delete(1.0, tk.END)
    raw_text.insert(tk.END, "Сканирование запущено...\n")

    root.update()

    target_id = get_or_create_target(target)

    scan_args = []
    if scanner != "zap" and arg:
        scan_args.append(arg)

    scan_id = create_scan(target_id, scanner, scan_args)

    raw_output = ""

    try:

        # ---------- NMAP ----------
        if scanner == "nmap":

            command = ["nmap"]

            if arg:
                command.append(arg)

            command.append(target)

            raw_output = run_command(command)

            services = parse_nmap(raw_output)

            save_services(target_id, services)

        # ---------- ZAP ----------
        elif scanner == "zap":

            raw_output, vulns = zap_scan(target)

            save_vulnerabilities(target_id, vulns)

        # ---------- WAPITI ----------
        elif scanner == "wapiti":

            raw_output, report_file = wapiti_scan(target, scan_args)

            time.sleep(2)

            issues = wapiti_parse(report_file)

            save_wapiti_issues(target_id, issues)

        finish_scan(scan_id, raw_output)

    except Exception:
        raw_output = "Ошибка при сканировании"

    raw_text.delete(1.0, tk.END)
    raw_text.insert(tk.END, raw_output)


# ---------------- REPORT ----------------

def generate_report():

    target = target_entry.get().strip()
    if not target:
        return

    target_id = get_or_create_target(target)

    nmap_text.delete(1.0, tk.END)
    zap_text.delete(1.0, tk.END)
    wapiti_text.delete(1.0, tk.END)

    # ---- NMAP ----
    for s in get_services(target_id):
        nmap_text.insert(tk.END,
            f"Порт: {s['port']}\n"
            f"Состояние: {translate_state(s['state'])}\n"
            f"Служба: {s['service']}\n"
            f"Версия: {translate_text(s['version'])}\n"
            "----------------------\n"
        )

    # ---- ZAP ----
    for v in get_vulnerabilities(target_id):
        zap_text.insert(tk.END,
            f"[{translate_risk(v['risk'])}] {v['alert']}\n"
            f"URL: {v['url']}\n"
            f"Описание: {translate_text(v['description'])}\n"
            "----------------------\n"
        )

    # ---- WAPITI ----
    for i in get_wapiti_issues(target_id):
        wapiti_text.insert(tk.END,
            f"[{translate_risk(i['level'])}] {i['type']}\n"
            f"URL: {i['url']}\n"
            f"Описание: {translate_text(i['info'])}\n"
            "----------------------\n"
        )


# ---------------- TRANSLATION ----------------

def translate_risk(r):
    return {
        "Low": "Низкий",
        "Medium": "Средний",
        "High": "Высокий",
        "Informational": "Информационный"
    }.get(r, r)


def translate_state(s):
    return {
        "open": "Открыт",
        "closed": "Закрыт",
        "filtered": "Фильтруется"
    }.get(s, s)


def translate_text(text):
    if not text:
        return ""

    words = {
        "server": "сервер",
        "version": "версия",
        "detected": "обнаружено",
        "vulnerability": "уязвимость",
    }

    for k, v in words.items():
        text = text.replace(k, v)

    return text


# ---------------- GUI ----------------

root = tk.Tk()
root.geometry("1100x650")
root.configure(bg="#0f172a")

style = ttk.Style()
style.theme_use("clam")

# Custom styles
style.configure("TFrame", background="#0f172a")
style.configure("Card.TFrame", background="#1e293b", relief="flat")
style.configure("TLabel", background="#0f172a", foreground="#e2e8f0", font=("Segoe UI", 10))
style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"), foreground="#f8fafc")
style.configure("TButton", font=("Segoe UI", 10), padding=6)
style.configure("Accent.TButton", background="#3b82f6", foreground="white")
style.map("Accent.TButton", background=[("active", "#2563eb")])

# --- MAIN LAYOUT ---
main_frame = ttk.Frame(root, padding=15)
main_frame.pack(fill="both", expand=True)

# LEFT PANEL (CONTROL)
left_frame = ttk.Frame(main_frame, style="Card.TFrame", padding=15)
left_frame.pack(side="left", fill="y", padx=(0, 10))

# RIGHT PANEL (OUTPUT)
right_frame = ttk.Frame(main_frame, style="Card.TFrame", padding=10)
right_frame.pack(side="right", fill="both", expand=True)

# --- LEFT CONTENT ---
ttk.Label(left_frame, text="Scanner Control", style="Header.TLabel").pack(anchor="w", pady=(0, 15))

scanner_var = tk.StringVar(value="nmap")
arg_var = tk.StringVar()

# Scanner select
ttk.Label(left_frame, text="Scanner").pack(anchor="w")
scanner_box = ttk.Combobox(
    left_frame,
    textvariable=scanner_var,
    values=SCANNERS,
    state="readonly"
)
scanner_box.pack(fill="x", pady=5)
scanner_box.bind("<<ComboboxSelected>>", on_scanner_change)
scanner_box.pack(fill="x", pady=5)

# Arguments
ttk.Label(left_frame, text="Arguments").pack(anchor="w", pady=(10, 0))
arg_box = ttk.Combobox(
    left_frame,
    textvariable=arg_var
)
arg_box.pack(fill="x", pady=5)
arg_box.bind("<<ComboboxSelected>>", on_argument_change)

# Target
ttk.Label(left_frame, text="Target").pack(anchor="w", pady=(10, 0))
target_entry = ttk.Entry(left_frame)
target_entry.pack(fill="x", pady=5)

# Buttons
ttk.Button(left_frame, text="Run Scan", style="Accent.TButton", command=run_scan).pack(fill="x", pady=(15, 5))
ttk.Button(left_frame, text="Generate Report", command=generate_report).pack(fill="x")

# --- RIGHT CONTENT ---
notebook = ttk.Notebook(right_frame)
notebook.pack(fill="both", expand=True)

# RAW TAB
raw_frame = ttk.Frame(notebook)
notebook.add(raw_frame, text="Raw Output")

raw_text = tk.Text(raw_frame, bg="#020617", fg="#38bdf8", insertbackground="white", relief="flat", font=("Consolas", 10))
raw_text.pack(fill="both", expand=True)

# REPORT TAB
report_frame = ttk.Frame(notebook)
notebook.add(report_frame, text="Reports")

report_notebook = ttk.Notebook(report_frame)
report_notebook.pack(fill="both", expand=True)

# Tabs
nmap_tab = ttk.Frame(report_notebook)
zap_tab = ttk.Frame(report_notebook)
wapiti_tab = ttk.Frame(report_notebook)

report_notebook.add(nmap_tab, text="Nmap")
report_notebook.add(zap_tab, text="ZAP")
report_notebook.add(wapiti_tab, text="Wapiti")

# Text areas
def create_text(parent):
    txt = tk.Text(parent, bg="#020617", fg="#e2e8f0", insertbackground="white", relief="flat", font=("Consolas", 10))
    txt.pack(fill="both", expand=True)
    return txt

nmap_text = create_text(nmap_tab)
zap_text = create_text(zap_tab)
wapiti_text = create_text(wapiti_tab)

on_scanner_change()

root.mainloop()
import tkinter as tk
from tkinter import ttk, messagebox
import threading

from scanners import nmap_scan, nikto_scan, zap_scan
from config.scanner_args import SCANNER_ARGUMENTS

SCANNERS = ["nmap", "nikto", "zap"]

def on_scanner_change(event=None):
    scanner = scanner_var.get()

    args = list(SCANNER_ARGUMENTS.get(scanner, {}).keys())
    arg_combo["values"] = args
    arg_var.set("")

    if scanner == "zap":
        arg_desc_var.set("OWASP ZAP использует API и не требует аргументов запуска")
    else:
        arg_desc_var.set("Выберите аргумент для просмотра описания")



def on_argument_change(event=None):
    scanner = scanner_var.get()
    arg = arg_var.get()

    if scanner == "zap":
        arg_desc_var.set("OWASP ZAP использует API и не требует аргументов запуска")
        return

    if arg:
        arg_desc_var.set(SCANNER_ARGUMENTS[scanner][arg])
    else:
        arg_desc_var.set("")


def run_scan():
    scanner = scanner_var.get()
    target = target_entry.get().strip()
    arg = arg_var.get()

    if not target:
        messagebox.showerror("Ошибка", "Введите IP-адрес или URL")
        return

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "Сканирование запущено...\n\n")

    def task():
        if scanner == "nmap":
            result = nmap_scan(target, [arg] if arg else [])

        elif scanner == "nikto":
            result = nikto_scan(target, [arg] if arg else [])

        elif scanner == "zap":
            result = zap_scan(target)

        else:
            result = "Неизвестный сканер"

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, result)

    threading.Thread(target=task, daemon=True).start()


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
arg_combo = ttk.Combobox(left_frame, textvariable=arg_var, state="readonly")
arg_combo.pack(fill="x", pady=5)
arg_combo.bind("<<ComboboxSelected>>", on_argument_change)

ttk.Label(
    left_frame,
    text="Описание аргумента:",
    font=("Segoe UI", 9, "bold")
).pack(anchor="w", pady=(10, 0))

arg_desc_var = tk.StringVar(value="Выберите аргумент для просмотра описания")
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

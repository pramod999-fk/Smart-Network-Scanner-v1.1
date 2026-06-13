"""
main.py  —  Smart Network Scanner v1.1
New in this version:
  • Real-time progress bar during scan
  • UDP scan toggle
  • Click a row to see full port details + remediation
  • Export HTML report (in addition to TXT)
  • Scan History tab — keeps a log across multiple scans
  • Dark / Light theme toggle
  • Folder picker when saving reports
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import ipaddress
import time
import webbrowser
import os

from scanner import scan_ports, is_host_reachable
from risk_analyzer import analyze_risk
from report_generator import generate_report

# ──────────────────────────────────────────────
#  App State
# ──────────────────────────────────────────────
results_data = []      # [port, service, risk, desc, cve, cvss, remediation]
udp_results  = []
scan_history = []      # [(timestamp, ip, open_count, high, medium, low)]
dark_mode    = True    # start in dark theme


# ──────────────────────────────────────────────
#  Stats helpers
# ──────────────────────────────────────────────
def update_stats():
    high   = sum(1 for r in results_data if r[2] == "High")
    medium = sum(1 for r in results_data if r[2] == "Medium")
    low    = sum(1 for r in results_data if r[2] == "Low")
    open_ports_var.set(str(len(results_data)))
    high_var.set(str(high))
    medium_var.set(str(medium))
    low_var.set(str(low))


# ──────────────────────────────────────────────
#  Detail popup
# ──────────────────────────────────────────────
def show_detail(event):
    selected = tree.focus()
    if not selected:
        return
    idx = tree.index(selected)
    if idx >= len(results_data):
        return
    row = results_data[idx]
    port, service, risk, desc, cve, cvss, remediation = row

    popup = tk.Toplevel(root)
    popup.title(f"Port {port} Details")
    popup.geometry("480x300")
    popup.configure(bg="#0f172a" if dark_mode else "#f1f5f9")
    fg = "white" if dark_mode else "#0f172a"
    bg = "#0f172a" if dark_mode else "#f1f5f9"

    def lbl(text, bold=False):
        font = ("Segoe UI", 11, "bold") if bold else ("Segoe UI", 10)
        tk.Label(popup, text=text, bg=bg, fg=fg, font=font,
                 anchor="w", wraplength=440, justify="left").pack(fill="x", padx=20, pady=2)

    lbl(f"Port {port} — {service}", bold=True)
    lbl(f"Risk Level : {risk}")
    lbl(f"CVSS Score : {cvss if cvss else '—'}")
    lbl(f"CVE        : {cve}")
    lbl(f"Description: {desc}")
    lbl("")
    lbl("Remediation:", bold=True)
    lbl(remediation)

    if cve != "N/A":
        def open_cve():
            webbrowser.open(f"https://nvd.nist.gov/vuln/detail/{cve}")
        tk.Button(popup, text="Open CVE in Browser", command=open_cve,
                  bg="#38bdf8", fg="white").pack(pady=10)


# ──────────────────────────────────────────────
#  Core scan
# ──────────────────────────────────────────────
def start_scan():
    global udp_results
    tree.delete(*tree.get_children())
    results_data.clear()
    udp_results = []
    update_stats()
    progress_var.set(0)

    ip = ip_entry.get().strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        messagebox.showerror("Error", "Invalid IP Address")
        _re_enable_buttons()
        return

    try:
        start_port = int(start_port_entry.get())
        end_port   = int(end_port_entry.get())
        timeout    = float(timeout_entry.get())
        if not (0 < start_port <= 65535 and 0 < end_port <= 65535 and start_port <= end_port):
            raise ValueError
    except ValueError:
        messagebox.showerror("Error", "Invalid port range (1–65535) or timeout value")
        _re_enable_buttons()
        return

    # Optional host reachability pre-check
    if check_host_var.get():
        status_var.set("Checking host reachability…")
        root.update_idletasks()
        if not is_host_reachable(ip, timeout):
            if not messagebox.askyesno(
                "Host May Be Unreachable",
                f"{ip} did not respond to probe connections.\n"
                "Continue scanning anyway?"
            ):
                _re_enable_buttons()
                status_var.set("Scan cancelled.")
                return

    status_var.set("Scanning…")
    scan_udp = udp_var.get()

    # Progress callback — called from worker thread
    total_ports = end_port - start_port + 1
    def on_progress(scanned, total):
        pct = int(scanned / total * 100)
        progress_var.set(pct)
        status_var.set(f"Scanning… {scanned}/{total} ports")

    start_time = time.time()
    open_tcp, open_udp = scan_ports(
        ip, start_port, end_port,
        timeout=timeout,
        scan_udp=scan_udp,
        progress_callback=on_progress,
    )
    udp_results = open_udp

    for port in open_tcp:
        service, risk, desc, cve, cvss, remediation = analyze_risk(port)
        results_data.append([port, service, risk, desc, cve, cvss, remediation])
        tree.insert("", "end",
                    values=(port, service, risk, cvss, cve),
                    tags=(risk,))

    update_stats()
    elapsed = round(time.time() - start_time, 2)
    progress_var.set(100)
    status_var.set(f"Scan Complete | {len(open_tcp)} TCP open | Time: {elapsed}s")

    # Log to history
    high   = sum(1 for r in results_data if r[2] == "High")
    medium = sum(1 for r in results_data if r[2] == "Medium")
    low    = sum(1 for r in results_data if r[2] == "Low")
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    scan_history.append((ts, ip, len(open_tcp), high, medium, low))
    history_tree.insert("", 0,
                         values=(ts, ip, len(open_tcp), high, medium, low))

    _re_enable_buttons()


def threaded_scan():
    scan_button.config(state="disabled")
    report_button.config(state="disabled")
    html_button.config(state="disabled")
    pdf_button.config(state="disabled")
    threading.Thread(target=start_scan, daemon=True).start()


def _re_enable_buttons():
    scan_button.config(state="normal")
    report_button.config(state="normal")
    html_button.config(state="normal")
    pdf_button.config(state="normal")


# ──────────────────────────────────────────────
#  Report export
# ──────────────────────────────────────────────
def save_report(fmt):
    if not results_data:
        messagebox.showwarning("Warning", "No scan results to export.")
        return

    folder = filedialog.askdirectory(title="Select folder to save report")
    if not folder:
        return

    txt_file, html_file, pdf_file = generate_report(
        ip_entry.get(), results_data, udp_results or None, fmt=fmt, folder=folder
    )
    if fmt == "txt":
        messagebox.showinfo("Saved", f"TXT report saved:\n{txt_file}")
    elif fmt == "html":
        messagebox.showinfo("Saved", f"HTML report saved:\n{html_file}")
        webbrowser.open(f"file://{os.path.abspath(html_file)}")
    elif fmt == "pdf":
        messagebox.showinfo("Saved", f"PDF report saved:\n{pdf_file}")
        webbrowser.open(f"file://{os.path.abspath(pdf_file)}")
    else:
        messagebox.showinfo("Saved",
                            f"Reports saved:\n• {txt_file}\n• {html_file}")
        webbrowser.open(f"file://{os.path.abspath(html_file)}")


# ──────────────────────────────────────────────
#  Theme toggle
# ──────────────────────────────────────────────
DARK  = {"bg": "#0f172a", "fg": "white", "entry_bg": "#1e293b", "entry_fg": "white"}
LIGHT = {"bg": "#f1f5f9", "fg": "#0f172a", "entry_bg": "white",   "entry_fg": "#0f172a"}

_all_bg_widgets  = []
_all_fg_widgets  = []
_all_entries     = []

def toggle_theme():
    global dark_mode
    dark_mode = not dark_mode
    t = DARK if dark_mode else LIGHT
    for w in _all_bg_widgets:
        try: w.configure(bg=t["bg"])
        except Exception: pass
    for w in _all_fg_widgets:
        try: w.configure(fg=t["fg"], bg=t["bg"])
        except Exception: pass
    for w in _all_entries:
        try: w.configure(bg=t["entry_bg"], fg=t["entry_fg"],
                          insertbackground=t["entry_fg"])
        except Exception: pass
    root.configure(bg=t["bg"])
    theme_btn.config(text="☀ Light Mode" if dark_mode else "🌙 Dark Mode")


def reg(widget, kind="bg"):
    """Register a widget for theme switching."""
    if kind == "fg":
        _all_fg_widgets.append(widget)
    elif kind == "entry":
        _all_entries.append(widget)
    else:
        _all_bg_widgets.append(widget)
    return widget


# ──────────────────────────────────────────────
#  GUI
# ──────────────────────────────────────────────
root = tk.Tk()
root.title("Smart Network Scanner v1.1")
root.geometry("1150x720")
root.configure(bg="#0f172a")

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview",
                background="#1e293b", foreground="white",
                rowheight=28, fieldbackground="#1e293b")
style.configure("Treeview.Heading",
                font=("Segoe UI", 11, "bold"),
                background="#1e293b", foreground="white")
style.configure("TProgressbar", troughcolor="#1e293b", background="#38bdf8")
style.configure("TNotebook", background="#0f172a", borderwidth=0)
style.configure("TNotebook.Tab",
                background="#1e293b", foreground="white",
                padding=(12, 6))
style.map("TNotebook.Tab",
          background=[("selected", "#38bdf8")],
          foreground=[("selected", "white")])

# Header
reg(tk.Label(root, text="🛡 Smart Network Scanner v1.1",
             bg="#0f172a", fg="#38bdf8",
             font=("Segoe UI", 18, "bold")), "fg").pack(pady=10)

# ── Input Row ──
input_frame = reg(tk.Frame(root, bg="#0f172a"))
input_frame.pack(pady=4, fill="x", padx=20)

def inp_lbl(text, col):
    w = reg(tk.Label(input_frame, text=text, bg="#0f172a", fg="white",
                     font=("Segoe UI", 10)), "fg")
    w.grid(row=0, column=col, padx=4, sticky="w")

def inp_entry(default, width, col):
    e = tk.Entry(input_frame, width=width, bg="#1e293b", fg="white",
                 insertbackground="white", relief="flat",
                 font=("Segoe UI", 10))
    e.insert(0, default)
    e.grid(row=0, column=col, padx=4)
    reg(e, "entry")
    return e

inp_lbl("Target IP:",   0); ip_entry         = inp_entry("127.0.0.1", 18, 1)
inp_lbl("Start Port:",  2); start_port_entry = inp_entry("1",         8,  3)
inp_lbl("End Port:",    4); end_port_entry   = inp_entry("10000",     8,  5)
inp_lbl("Timeout(s):",  6); timeout_entry    = inp_entry("1.0",       6,  7)

# Options row
opts_frame = reg(tk.Frame(root, bg="#0f172a"))
opts_frame.pack(pady=2, fill="x", padx=20)

udp_var = tk.BooleanVar(value=False)
check_host_var = tk.BooleanVar(value=True)

udp_chk = tk.Checkbutton(opts_frame, text="Include UDP scan",
                           variable=udp_var,
                           bg="#0f172a", fg="#94a3b8",
                           selectcolor="#1e293b",
                           activebackground="#0f172a",
                           font=("Segoe UI", 10))
udp_chk.pack(side="left", padx=10)
reg(udp_chk)

host_chk = tk.Checkbutton(opts_frame, text="Pre-check host reachability",
                            variable=check_host_var,
                            bg="#0f172a", fg="#94a3b8",
                            selectcolor="#1e293b",
                            activebackground="#0f172a",
                            font=("Segoe UI", 10))
host_chk.pack(side="left", padx=10)
reg(host_chk)

theme_btn = tk.Button(opts_frame, text="☀ Light Mode",
                       command=toggle_theme,
                       bg="#334155", fg="white",
                       relief="flat", font=("Segoe UI", 10))
theme_btn.pack(side="right", padx=10)

# ── Buttons Row ──
button_frame = reg(tk.Frame(root, bg="#0f172a"))
button_frame.pack(pady=6)

scan_button = tk.Button(button_frame, text="▶  Start Scan",
                         command=threaded_scan,
                         bg="#38bdf8", fg="white",
                         width=14, font=("Segoe UI", 10, "bold"), relief="flat")
scan_button.pack(side="left", padx=8)

report_button = tk.Button(button_frame, text="💾  Save TXT",
                           command=lambda: save_report("txt"),
                           bg="#6366f1", fg="white",
                           width=13, font=("Segoe UI", 10, "bold"), relief="flat")
report_button.pack(side="left", padx=8)

html_button = tk.Button(button_frame, text="🌐  Export HTML",
                         command=lambda: save_report("html"),
                         bg="#22c55e", fg="white",
                         width=14, font=("Segoe UI", 10, "bold"), relief="flat")
html_button.pack(side="left", padx=8)

pdf_button = tk.Button(button_frame, text="📄  Export PDF",
                        command=lambda: save_report("pdf"),
                        bg="#f97316", fg="white",
                        width=13, font=("Segoe UI", 10, "bold"), relief="flat")
pdf_button.pack(side="left", padx=8)

# ── Stats Cards ──
stats_frame = reg(tk.Frame(root, bg="#0f172a"))
stats_frame.pack(pady=8, fill="x", padx=20)

open_ports_var = tk.StringVar(value="0")
high_var       = tk.StringVar(value="0")
medium_var     = tk.StringVar(value="0")
low_var        = tk.StringVar(value="0")
status_var     = tk.StringVar(value="Ready")
progress_var   = tk.IntVar(value=0)

def create_card(parent, title, var, color):
    frame = tk.Frame(parent, bg=color)
    frame.pack(side="left", padx=8, expand=True, fill="x")
    tk.Label(frame, text=title, bg=color, fg="white",
             font=("Segoe UI", 9, "bold")).pack(pady=(6, 0))
    tk.Label(frame, textvariable=var, bg=color, fg="white",
             font=("Segoe UI", 18, "bold")).pack(pady=(0, 6))

create_card(stats_frame, "OPEN PORTS", open_ports_var, "#2563eb")
create_card(stats_frame, "HIGH",       high_var,       "#ef4444")
create_card(stats_frame, "MEDIUM",     medium_var,     "#f59e0b")
create_card(stats_frame, "LOW",        low_var,        "#22c55e")

# Status + progress
status_label = reg(tk.Label(root, textvariable=status_var,
                             bg="#0f172a", fg="#22c55e",
                             font=("Segoe UI", 10)), "fg")
status_label.pack()

progress_bar = ttk.Progressbar(root, variable=progress_var,
                                 maximum=100, style="TProgressbar")
progress_bar.pack(fill="x", padx=20, pady=4)

# ── Notebook (tabs) ──
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=10, pady=6)

# Tab 1: Results
results_tab = reg(tk.Frame(notebook, bg="#0f172a"))
notebook.add(results_tab, text="  Scan Results  ")

tree = ttk.Treeview(results_tab,
                    columns=("Port", "Service", "Risk", "CVSS", "CVE"),
                    show="headings")
for col, w in [("Port", 70), ("Service", 160), ("Risk", 80),
               ("CVSS", 70), ("CVE", 160)]:
    tree.heading(col, text=col)
    tree.column(col, width=w, anchor="center" if col in ("Port","Risk","CVSS") else "w")
tree.pack(fill="both", expand=True, padx=4, pady=4)
tree.tag_configure("High",   foreground="#ef4444")
tree.tag_configure("Medium", foreground="#f59e0b")
tree.tag_configure("Low",    foreground="#22c55e")
tree.bind("<Double-1>", show_detail)

hint = reg(tk.Label(results_tab,
                     text="Double-click a row for full details and remediation advice.",
                     bg="#0f172a", fg="#475569",
                     font=("Segoe UI", 9)), "fg")
hint.pack()

# Tab 2: History
history_tab = reg(tk.Frame(notebook, bg="#0f172a"))
notebook.add(history_tab, text="  Scan History  ")

history_tree = ttk.Treeview(history_tab,
                              columns=("Time", "IP", "Open", "High", "Medium", "Low"),
                              show="headings")
for col, w in [("Time", 160), ("IP", 130), ("Open", 70),
               ("High", 70), ("Medium", 80), ("Low", 70)]:
    history_tree.heading(col, text=col)
    history_tree.column(col, width=w, anchor="center")
history_tree.pack(fill="both", expand=True, padx=4, pady=4)

def clear_history():
    scan_history.clear()
    history_tree.delete(*history_tree.get_children())

tk.Button(history_tab, text="Clear History", command=clear_history,
          bg="#ef4444", fg="white", relief="flat").pack(pady=6)

root.mainloop()

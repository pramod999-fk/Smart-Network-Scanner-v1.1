# 🛡 Smart Network Scanner v1.1

A Python-based GUI tool that scans a target host for open TCP/UDP ports, analyzes the risk level of each discovered service, and generates detailed vulnerability reports (TXT, HTML, and PDF).

Built with **Tkinter** for the interface and **multithreading** for fast scanning — created as a college project.

---

## ✨ Features

- **Port Scanning** — scan a custom range of TCP ports on any target IP
- **UDP Scan Toggle** — optionally include UDP port scanning
- **Host Reachability Check** — pre-checks if the target host is reachable before scanning
- **Real-Time Progress Bar** — live progress updates while scanning
- **Risk Analysis** — classifies each open port as High / Medium / Low risk with CVE references and CVSS scores
- **Port Details Popup** — double-click any result row to view full description and remediation advice
- **Scan History Tab** — keeps a log of all scans performed during the session
- **Dark / Light Theme Toggle**
- **Export Reports** — save results as:
  - 📄 PDF report
  - 🌐 HTML report (auto-opens in browser)
  - 📝 TXT report
- **Folder Picker** — choose where to save your reports

---

## 🖥 Screenshots

*(Add screenshots of the app here)*

---

## 📦 Requirements

- Python 3.8+
- Dependencies:
  ```
  pip install reportlab
  ```
  (Tkinter comes pre-installed with Python on Windows)

---

## ▶ Running the App

```bash
python main.py
```

---

## 🏗 Building a Windows EXE

A ready-made build script is included.

1. Make sure all project files (`main.py`, `scanner.py`, `risk_analyzer.py`, `report_generator.py`, `build_exe.bat`) are in the same folder.
2. Double-click **`build_exe.bat`**.
3. The script will:
   - Install PyInstaller and reportlab
   - Build a standalone `.exe` using PyInstaller
4. Find the generated executable inside the **`dist`** folder.

---

## 📂 Project Structure

```
├── main.py              # GUI application (entry point)
├── scanner.py           # Port scanning logic (TCP/UDP + host check)
├── risk_analyzer.py     # Maps ports to services, risk levels, CVEs, remediation
├── report_generator.py  # Generates TXT / HTML / PDF reports
└── build_exe.bat        # Builds a standalone Windows executable
```

---

## ⚠ Disclaimer

This tool is intended for **educational purposes only**. Only scan hosts and networks you own or have explicit permission to test. Unauthorized scanning of networks may be illegal.

---

## 📜 License

This project is for academic/educational use. Add a license of your choice if distributing publicly.

from datetime import datetime
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def generate_report(ip, results, udp_results=None, fmt="both", folder="."):
    """
    results: list of [port, service, risk, desc, cve, cvss, remediation]
    udp_results: list of open UDP ports (ints) or None
    fmt: "txt", "html", "pdf", or "both" (txt+html)
    Returns (txt_file_path, html_file_path, pdf_file_path) — unused ones are None.
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    txt_path = None
    html_path = None
    pdf_path = None


    if fmt in ("txt", "both"):
        txt_filename = f"Network_Report_{timestamp}.txt"
        txt_path = os.path.join(folder, txt_filename)
        with open(txt_path, "w") as f:
            f.write("SMART NETWORK VULNERABILITY SCANNER REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f"Target IP : {ip}\n")
            f.write(f"Scan Date : {datetime.now()}\n\n")

            f.write("TCP OPEN PORTS\n")
            f.write("-" * 70 + "\n")
            f.write(f"{'Port':<6}{'Service':<22}{'Risk':<8}{'CVSS':<6}{'CVE':<18}\n")
            f.write("-" * 70 + "\n")
            for row in results:
                port, service, risk, desc, cve, cvss, remediation = row
                cvss_str = str(cvss) if cvss is not None else "—"
                f.write(f"{port:<6}{service:<22}{risk:<8}{cvss_str:<6}{cve:<18}\n")
                f.write(f"       Description : {desc}\n")
                f.write(f"       Remediation : {remediation}\n\n")

            if udp_results:
                f.write("\nUDP OPEN PORTS\n")
                f.write("-" * 70 + "\n")
                for port in udp_results:
                    f.write(f"{port}\n")

    if fmt in ("html", "both"):
        html_filename = f"Network_Report_{timestamp}.html"
        html_path = os.path.join(folder, html_filename)

        risk_colors = {"High": "#ef4444", "Medium": "#f59e0b", "Low": "#22c55e"}

        rows_html = ""
        for row in results:
            port, service, risk, desc, cve, cvss, remediation = row
            cvss_str = str(cvss) if cvss is not None else "—"
            color = risk_colors.get(risk, "#94a3b8")
            rows_html += f"""
            <tr>
                <td>{port}</td>
                <td>{service}</td>
                <td><span style="color:{color}; font-weight:bold;">{risk}</span></td>
                <td>{cvss_str}</td>
                <td>{cve}</td>
                <td>{desc}</td>
                <td>{remediation}</td>
            </tr>"""

        udp_html = ""
        if udp_results:
            udp_items = "".join(f"<li>Port {p}</li>" for p in udp_results)
            udp_html = f"""
            <h2>UDP Open Ports</h2>
            <ul>{udp_items}</ul>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Scan Report - {ip}</title>
<style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 30px; }}
    h1 {{ color: #38bdf8; }}
    h2 {{ color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 6px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ border: 1px solid #334155; padding: 8px 10px; text-align: left; font-size: 14px; }}
    th {{ background: #1e293b; color: #38bdf8; }}
    tr:nth-child(even) {{ background: #1e293b; }}
    .meta {{ color: #94a3b8; margin-bottom: 20px; }}
</style>
</head>
<body>
    <h1>🛡 Smart Network Vulnerability Scanner Report</h1>
    <p class="meta">
        Target IP: <strong>{ip}</strong><br>
        Scan Date: {datetime.now()}
    </p>

    <h2>TCP Open Ports</h2>
    <table>
        <tr>
            <th>Port</th><th>Service</th><th>Risk</th><th>CVSS</th>
            <th>CVE</th><th>Description</th><th>Remediation</th>
        </tr>
        {rows_html if rows_html else "<tr><td colspan='7'>No open TCP ports found.</td></tr>"}
    </table>
    {udp_html}
</body>
</html>"""

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    if fmt == "pdf":
        pdf_filename = f"Network_Report_{timestamp}.pdf"
        pdf_path = os.path.join(folder, pdf_filename)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "TitleCustom", parent=styles["Title"], textColor=colors.HexColor("#0f172a")
        )
        heading_style = ParagraphStyle(
            "HeadingCustom", parent=styles["Heading2"], textColor=colors.HexColor("#1e3a8a")
        )
        normal_style = styles["Normal"]

        story = []
        story.append(Paragraph("Smart Network Vulnerability Scanner Report", title_style))
        story.append(Spacer(1, 8))
        story.append(Paragraph(f"Target IP: {ip}", normal_style))
        story.append(Paragraph(f"Scan Date: {datetime.now()}", normal_style))
        story.append(Spacer(1, 16))

        story.append(Paragraph("TCP Open Ports", heading_style))
        story.append(Spacer(1, 6))

        risk_colors = {
            "High": colors.HexColor("#ef4444"),
            "Medium": colors.HexColor("#f59e0b"),
            "Low": colors.HexColor("#16a34a"),
        }

        if results:
            table_data = [["Port", "Service", "Risk", "CVSS", "CVE", "Description", "Remediation"]]
            for row in results:
                port, service, risk, desc, cve, cvss, remediation = row
                cvss_str = str(cvss) if cvss is not None else "-"
                table_data.append([
                    str(port),
                    Paragraph(service, normal_style),
                    risk,
                    cvss_str,
                    cve,
                    Paragraph(desc, normal_style),
                    Paragraph(remediation, normal_style),
                ])

            col_widths = [35, 75, 45, 35, 65, 130, 130]
            tbl = Table(table_data, colWidths=col_widths, repeatRows=1)

            tbl_style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
            ]
            for i, row in enumerate(results, start=1):
                risk = row[2]
                if risk in risk_colors:
                    tbl_style.append(("TEXTCOLOR", (2, i), (2, i), risk_colors[risk]))
                    tbl_style.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))

            tbl.setStyle(TableStyle(tbl_style))
            story.append(tbl)
        else:
            story.append(Paragraph("No open TCP ports found.", normal_style))

        if udp_results:
            story.append(Spacer(1, 16))
            story.append(Paragraph("UDP Open Ports", heading_style))
            story.append(Spacer(1, 6))
            udp_text = ", ".join(str(p) for p in udp_results)
            story.append(Paragraph(udp_text, normal_style))

        doc = SimpleDocTemplate(pdf_path, pagesize=letter,
                                 topMargin=40, bottomMargin=40,
                                 leftMargin=30, rightMargin=30)
        doc.build(story)

    return txt_path, html_path, pdf_path

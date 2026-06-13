def analyze_risk(port):
    """
    Returns: (service, risk, description, cve, cvss, remediation)
    """
    port_info = {
        21: ("FTP", "Medium", "File Transfer Protocol", "CVE-2015-3306", 7.5,
             "Disable anonymous FTP, use SFTP/FTPS instead, and restrict access via firewall."),
        22: ("SSH", "Low", "Secure Remote Login", "N/A", None,
             "Use key-based authentication, disable root login, and keep SSH updated."),
        23: ("Telnet", "High", "Unencrypted Remote Access", "CVE-2016-10401", 9.8,
             "Disable Telnet entirely and use SSH instead — Telnet sends credentials in plaintext."),
        25: ("SMTP", "Medium", "Mail Transfer Service", "N/A", None,
             "Ensure relay restrictions are in place and enable TLS for mail transport."),
        53: ("DNS", "Low", "Domain Name Service", "N/A", None,
             "Restrict zone transfers and recursive queries to trusted clients only."),
        80: ("HTTP", "Low", "Web Server", "N/A", None,
             "Redirect to HTTPS, keep the web server patched, and disable directory listing."),
        110: ("POP3", "Medium", "Email Retrieval", "N/A", None,
              "Use POP3S (encrypted) instead of plain POP3."),
        135: ("RPC", "Low", "Windows RPC Service", "N/A", None,
              "Restrict RPC endpoint access via firewall to trusted hosts only."),
        143: ("IMAP", "Medium", "Email Access", "N/A", None,
              "Use IMAPS (encrypted) instead of plain IMAP."),
        443: ("HTTPS", "Low", "Secure Web Service", "N/A", None,
              "Keep TLS certificates and ciphers up to date; disable old TLS versions."),
        445: ("SMB", "High", "Windows File Sharing", "CVE-2017-0144", 8.1,
              "Patch against EternalBlue, disable SMBv1, and restrict access to trusted networks."),
        623: ("IPMI", "Medium", "Remote Server Management", "CVE-2013-4786", 5.0,
              "Change default IPMI credentials and restrict access to a management VLAN."),
        3306: ("MySQL", "Medium", "Database Service", "N/A", None,
               "Bind MySQL to localhost or trusted hosts only, and enforce strong passwords."),
        3389: ("RDP", "High", "Remote Desktop Service", "CVE-2019-0708", 9.8,
               "Enable Network Level Authentication, patch BlueKeep, and restrict via VPN/firewall."),
        5432: ("PostgreSQL", "Medium", "Database Service", "N/A", None,
               "Restrict pg_hba.conf access and avoid exposing the database to the internet."),
        8000: ("Python HTTP Server", "Low", "Local Web Server", "N/A", None,
               "Ensure this is not exposed publicly; use only for local development."),
        8080: ("HTTP Alternate", "Low", "Alternative Web Service", "N/A", None,
               "Same as HTTP — use HTTPS and keep the service patched."),
    }
    return port_info.get(
        port,
        ("Custom Service", "Low", "Unknown Service", "N/A", None,
         "Investigate this service manually to determine its purpose and risk.")
    )

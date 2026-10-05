#!/usr/bin/env python3
"""rtunnel netmon: reports the pod's network interface byte counters as JSON.

Runs as a sidecar in the rtunnel pod, sharing its network namespace with the
ssh/dns containers, so /proc/net/dev reflects the actual tunnel traffic.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_PORT = int(os.environ.get("PORT", "8090"))


def read_counters():
    rx = tx = 0
    with open("/proc/net/dev") as f:
        next(f)
        next(f)
        for line in f:
            name, rest = line.split(":", 1)
            if name.strip() == "lo":
                continue
            fields = rest.split()
            rx += int(fields[0])
            tx += int(fields[8])
    return rx, tx


class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/metrics":
            rx, tx = read_counters()
            self.send(200, json.dumps({"rx_bytes": rx, "tx_bytes": tx}).encode(), "application/json")
        elif self.path == "/healthz":
            self.send(200, b"ok", "text/plain")
        else:
            self.send(404, b"not found", "text/plain")

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()

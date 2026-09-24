#!/usr/bin/env python3
"""rtunnel status page: probes the tunnel through its Service, serves HTML + JSON."""
import json
import os
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("TUNNEL_HOST", "rtunnel")
LB_IP = os.environ.get("LB_IP", "")
DNS_NAME = os.environ.get("DNS_TEST_NAME", "rutgers.edu")
INTERVAL = int(os.environ.get("CHECK_INTERVAL", "30"))
SSH_CONFIG = os.environ.get("SSH_CONFIG", "/etc/rtunnel/ssh_config")
LISTEN_PORT = int(os.environ.get("PORT", "8080"))
TIMEOUT = 6
PORTS = {"socks": 1080, "smb": 445, "udns": 5353, "unbound": 5354}
RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

LOCK = threading.Lock()
STATE = {}
REFRESH = threading.Event()
LAST_RUN = [0.0]


def ms(t0):
    return round((time.monotonic() - t0) * 1000)


def read_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("connection closed by remote (tunnel forward failed?)")
        buf += chunk
    return buf


def check_socks():
    t = time.monotonic()
    with socket.create_connection((HOST, PORTS["socks"]), TIMEOUT) as s:
        s.settimeout(TIMEOUT)
        s.sendall(b"\x05\x01\x00")
        reply = read_exact(s, 2)
    if reply != b"\x05\x00":
        raise RuntimeError("unexpected SOCKS reply %r" % reply)
    return ms(t), "SOCKS5 handshake ok"


def smb2_negotiate():
    header = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) + b"\x00" * 16
    body = struct.pack("<HHHHI", 36, 2, 1, 0, 0) + os.urandom(16) + b"\x00" * 8 + struct.pack("<HH", 0x0202, 0x0210)
    payload = header + body
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def check_smb():
    with socket.create_connection((HOST, PORTS["smb"]), TIMEOUT) as s:
        s.settimeout(TIMEOUT)
        t = time.monotonic()
        s.sendall(smb2_negotiate())
        head = read_exact(s, 4)
        resp = read_exact(s, min(int.from_bytes(head[1:], "big"), 70))
    elapsed = ms(t)
    if resp[:4] not in (b"\xfeSMB", b"\xffSMB"):
        raise RuntimeError("reply was not SMB")
    dialect = struct.unpack("<H", resp[68:70])[0] if len(resp) >= 70 else None
    detail = "SMB2 negotiate ok" + (" (dialect 0x%04x)" % dialect if dialect else "")
    return elapsed, detail


def skip_name(buf, i):
    while True:
        n = buf[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n


def check_dns(port):
    qid = int.from_bytes(os.urandom(2), "big")
    labels = b"".join(bytes([len(p)]) + p.encode() for p in DNS_NAME.strip(".").split("."))
    query = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)
    addr = socket.getaddrinfo(HOST, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    t = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        s.sendto(query, addr)
        buf, _ = s.recvfrom(4096)
    elapsed = ms(t)
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", buf[:12])
    if rid != qid:
        raise RuntimeError("mismatched DNS transaction id")
    rcode = flags & 0xF
    if rcode:
        raise RuntimeError("%s for %s" % (RCODES.get(rcode, "rcode %d" % rcode), DNS_NAME))
    i = 12
    for _ in range(qd):
        i = skip_name(buf, i) + 4
    ips = []
    for _ in range(an):
        i = skip_name(buf, i)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", buf[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(buf[i:i + 4]))
        i += rdlen
    return elapsed, "%s → %s" % (DNS_NAME, ", ".join(ips[:3]) or "no A records")


CHECKS = [
    ("ssh", "SSH tunnel", "Local SOCKS listener answers, so the ssh client is running", check_socks),
    ("smb", "SMB forward", "SMB2 negotiate through the tunnel to the file server", check_smb),
    ("udns", "DNS · udns", "UDP query to CoreDNS, forwarded over TCP through the tunnel", lambda: check_dns(PORTS["udns"])),
    ("unbound", "DNS · unbound", "UDP query to CoreDNS, forwarded over TCP through the tunnel", lambda: check_dns(PORTS["unbound"])),
]


def run_check(key, fn):
    try:
        latency, detail = fn()
        ok = True
    except Exception as e:
        latency, detail, ok = None, "%s: %s" % (type(e).__name__, e), False
    now = time.time()
    with LOCK:
        prev = STATE.get(key)
        since = prev["since"] if prev and prev["ok"] == ok else now
        STATE[key] = {"ok": ok, "detail": detail, "ms": latency, "since": since, "checked": now}


def check_loop():
    with ThreadPoolExecutor(max_workers=len(CHECKS)) as pool:
        while True:
            list(pool.map(lambda c: run_check(c[0], c[3]), CHECKS))
            LAST_RUN[0] = time.time()
            REFRESH.wait(INTERVAL)
            REFRESH.clear()


def read_config():
    info = {"jump": "", "forwards": []}
    host = user = ""
    try:
        with open(SSH_CONFIG) as f:
            for line in f:
                p = line.split()
                if len(p) >= 2 and p[0] == "HostName":
                    host = p[1]
                elif len(p) >= 2 and p[0] == "User":
                    user = p[1]
                elif len(p) >= 3 and p[0] == "LocalForward" and not p[1].startswith("127."):
                    info["forwards"].append("local :%s → %s" % (p[1].split(":")[-1], p[2]))
                elif len(p) >= 2 and p[0] == "DynamicForward":
                    info["forwards"].append("SOCKS :%s (dynamic)" % p[1].split(":")[-1])
    except OSError:
        pass
    info["jump"] = "%s@%s" % (user, host) if host else ""
    return info


def snapshot():
    now = time.time()
    checks = []
    with LOCK:
        for key, name, desc, _ in CHECKS:
            s = STATE.get(key)
            row = {"key": key, "name": name, "desc": desc, "ok": None}
            if s:
                row.update(ok=s["ok"], detail=s["detail"], ms=s["ms"],
                           since_s=round(now - s["since"]), checked_s=round(now - s["checked"]))
            checks.append(row)
    known = [c for c in checks if c["ok"] is not None]
    if len(known) < len(checks):
        overall = "checking"
    elif not checks[0]["ok"]:
        overall = "down"
    elif all(c["ok"] for c in checks):
        overall = "ok"
    else:
        overall = "degraded"
    cfg = read_config()
    ip = LB_IP or HOST
    endpoints = [
        {"name": "SMB", "addr": "%s:445" % ip, "proto": "TCP"},
        {"name": "SOCKS5", "addr": "%s:1080" % ip, "proto": "TCP"},
        {"name": "DNS · udns", "addr": "%s:5353" % ip, "proto": "UDP/TCP"},
        {"name": "DNS · unbound", "addr": "%s:5354" % ip, "proto": "UDP/TCP"},
    ]
    return {"overall": overall, "checks": checks, "endpoints": endpoints, "jump": cfg["jump"],
            "forwards": cfg["forwards"], "interval": INTERVAL, "dns_test": DNS_NAME}


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rtunnel status</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
:root {
  --bg: #f6f7f9; --card: #ffffff; --text: #1b1f24; --muted: #5c6670; --line: #dde1e6;
  --ok: #1a7f37; --ok-bg: #dafbe1; --warn: #9a6700; --warn-bg: #fff8c5;
  --bad: #cf222e; --bad-bg: #ffebe9; --idle: #57606a; --idle-bg: #eaeef2;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --card: #161b22; --text: #e6edf3; --muted: #8b949e; --line: #30363d;
    --ok: #3fb950; --ok-bg: #12261a; --warn: #d29922; --warn-bg: #2a2110;
    --bad: #f85149; --bad-bg: #2d1416; --idle: #8b949e; --idle-bg: #21262d;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 860px; margin: 0 auto; padding: 24px 16px 48px; }
header { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 20px; }
h1 { font-size: 22px; margin: 0; }
.sub { color: var(--muted); font-size: 13px; }
.pill { display: inline-flex; align-items: center; gap: 8px; padding: 6px 14px; border-radius: 999px;
  font-weight: 600; font-size: 14px; background: var(--idle-bg); color: var(--idle); }
.pill.ok { background: var(--ok-bg); color: var(--ok); }
.pill.degraded { background: var(--warn-bg); color: var(--warn); }
.pill.down { background: var(--bad-bg); color: var(--bad); }
.dot { width: 10px; height: 10px; border-radius: 50%; background: currentColor; flex: none; }
section { margin-top: 28px; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 0 0 10px; }
.grid { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
.card .top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.card .name { font-weight: 600; }
.badge { font-size: 12px; font-weight: 600; padding: 2px 10px; border-radius: 999px; background: var(--idle-bg); color: var(--idle); }
.badge.ok { background: var(--ok-bg); color: var(--ok); }
.badge.bad { background: var(--bad-bg); color: var(--bad); }
.detail { margin-top: 6px; font-size: 13px; overflow-wrap: anywhere; }
.detail.bad { color: var(--bad); }
.meta { margin-top: 4px; font-size: 12px; color: var(--muted); }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line);
  border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: 9px 14px; border-bottom: 1px solid var(--line); font-size: 14px; }
th { font-size: 12px; color: var(--muted); font-weight: 600; }
tr:last-child td { border-bottom: 0; }
code { font: 13px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
ul { margin: 0; padding-left: 18px; }
button { font: inherit; font-size: 13px; padding: 5px 12px; border-radius: 8px; cursor: pointer;
  border: 1px solid var(--line); background: var(--card); color: var(--text); }
button:hover { border-color: var(--muted); }
.stale { opacity: .55; }
</style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>rtunnel</h1>
      <div class="sub" id="jump">SSH tunnel to the Rutgers jump host</div>
    </div>
    <div style="display:flex;align-items:center;gap:10px">
      <span class="pill" id="overall"><span class="dot"></span><span id="overall-text">Checking…</span></span>
      <button id="refresh" type="button">Check now</button>
    </div>
  </header>

  <section>
    <h2>Health checks</h2>
    <div class="grid" id="checks"></div>
    <div class="sub" id="footer" style="margin-top:10px"></div>
  </section>

  <section>
    <h2>Connect to</h2>
    <table>
      <thead><tr><th>Service</th><th>Address</th><th>Protocol</th></tr></thead>
      <tbody id="endpoints"></tbody>
    </table>
  </section>

  <section>
    <h2>Forwards on the jump host</h2>
    <div class="card"><ul id="forwards"></ul></div>
  </section>
</main>
<script>
const $ = (s) => document.querySelector(s);
const LABELS = { ok: "Healthy", degraded: "Degraded", down: "Down", checking: "Checking…" };

function dur(s) {
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
  return Math.floor(s / 86400) + "d " + Math.floor((s % 86400) / 3600) + "h";
}
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}
function render(d) {
  document.body.classList.remove("stale");
  const pill = $("#overall");
  pill.className = "pill " + d.overall;
  $("#overall-text").textContent = LABELS[d.overall] || d.overall;
  $("#jump").textContent = d.jump ? "SSH tunnel to " + d.jump : "SSH tunnel to the Rutgers jump host";

  const checks = $("#checks");
  checks.replaceChildren();
  let newest = null;
  for (const c of d.checks) {
    const card = el("div", "card");
    const top = el("div", "top");
    top.append(el("span", "name", c.name));
    const state = c.ok === null ? "Pending" : c.ok ? "Up" : "Down";
    top.append(el("span", "badge " + (c.ok === null ? "" : c.ok ? "ok" : "bad"), state));
    card.append(top);
    if (c.detail) card.append(el("div", "detail" + (c.ok ? "" : " bad"), c.detail));
    let meta = c.desc;
    if (c.ok !== null) {
      meta = (c.ms !== null ? c.ms + " ms · " : "") + (c.ok ? "up " : "down ") + "for " + dur(c.since_s);
      if (newest === null || c.checked_s < newest) newest = c.checked_s;
    }
    card.append(el("div", "meta", meta));
    checks.append(card);
  }
  $("#footer").textContent = newest === null ? "Waiting for the first check…" :
    "Last checked " + dur(newest) + " ago · checks run every " + d.interval + "s · DNS test name: " + d.dns_test;

  const eps = $("#endpoints");
  eps.replaceChildren();
  for (const e of d.endpoints) {
    const tr = el("tr");
    tr.append(el("td", "", e.name));
    const td = el("td");
    td.append(el("code", "", e.addr));
    tr.append(td, el("td", "", e.proto));
    eps.append(tr);
  }
  const fw = $("#forwards");
  fw.replaceChildren();
  for (const f of d.forwards) { const li = el("li"); li.append(el("code", "", f)); fw.append(li); }
  if (!d.forwards.length) fw.append(el("li", "", "No forwards configured"));
}
async function load() {
  try {
    const r = await fetch("/api/status", { cache: "no-store" });
    if (!r.ok) throw new Error(r.status);
    render(await r.json());
  } catch (e) {
    document.body.classList.add("stale");
    $("#overall").className = "pill";
    $("#overall-text").textContent = "Status page unreachable";
  }
}
$("#refresh").addEventListener("click", async () => {
  try { await fetch("/api/refresh", { method: "POST" }); } catch (e) {}
  setTimeout(load, 2500);
});
load();
setInterval(load, 5000);
</script>
</body>
</html>
""".encode()

# Rutgers scarlet (#CC0033) tile with a white R
FAVICON = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<rect width="64" height="64" rx="14" fill="#cc0033"/>
<text x="32" y="47" text-anchor="middle" font-family="Georgia, 'Times New Roman', serif" font-size="42" font-weight="700" fill="#fff">R</text>
</svg>
"""


class Handler(BaseHTTPRequestHandler):
    def send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self.send(200, PAGE, "text/html; charset=utf-8")
        elif path == "/api/status":
            self.send(200, json.dumps(snapshot()).encode(), "application/json")
        elif path == "/favicon.svg":
            self.send(200, FAVICON, "image/svg+xml")
        elif path == "/healthz":
            self.send(200, b"ok", "text/plain")
        else:
            self.send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path == "/api/refresh":
            if time.time() - LAST_RUN[0] > 5:
                REFRESH.set()
            self.send(202, b"{}", "application/json")
        else:
            self.send(404, b"not found", "text/plain")

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    threading.Thread(target=check_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()

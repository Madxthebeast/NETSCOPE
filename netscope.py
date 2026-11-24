#!/usr/bin/env python3
"""
NetScope - Network Security, Intelligence & Assessment Platform
================================================================
Single-file desktop application (PySide6) for Windows 10/11 and Linux.

Use ONLY against systems you own or are explicitly authorized to assess.

Run:   python netscope.py
Tests: python netscope.py --selftest      (engine tests, no GUI / no network)
Check: python netscope.py --check         (dependency diagnostics)
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import html
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from urllib.parse import urlparse

APP_NAME = "NetScope"
APP_VERSION = "1.2"
ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"

# Hide console windows when spawning tools from the GUI on Windows.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


# =============================================================================
# CORE: storage, platform detection
# =============================================================================
def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class JsonStore:
    """Append-only JSONL store. One folder per bucket under `base`."""

    def __init__(self, base=None):
        self.base = Path(base) if base else DATA_DIR
        self.base.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, bucket: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_\-]+", bucket):
            raise ValueError("Invalid bucket name.")
        p = self.base / bucket
        p.mkdir(parents=True, exist_ok=True)
        return p / "records.jsonl"

    def append(self, bucket: str, record: dict) -> dict:
        item = dict(record)
        item.setdefault("id", str(uuid.uuid4()))
        item.setdefault("created_at", utcnow())
        line = json.dumps(item, ensure_ascii=False, default=str)
        with self._lock:
            with self._path(bucket).open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        return item

    def read(self, bucket: str) -> list:
        path = self._path(bucket)
        records = []
        if not path.exists():
            return records
        with self._lock, path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # tolerate a damaged line
        return records

    def read_json(self, relative: str, default=None):
        path = self.base / relative
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

    def count(self, bucket: str) -> int:
        return len(self.read(bucket))

    def write_json(self, relative: str, payload) -> Path:
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".netscope-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return path


TOOLS = ["nmap", "rustscan", "tshark", "wireshark", "dnsrecon", "whois", "netdiscover",
         "arp-scan", "masscan", "gobuster", "dirsearch", "nikto", "zaproxy", "gvm-cli",
         "kismet", "aircrack-ng", "john", "hashcat", "ghidra", "yara", "autopsy",
         "volatility", "msfconsole", "dig", "nslookup", "traceroute", "tracepath", "tracert"]


def _windows_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def detect_platform() -> dict:
    if os.name == "nt":
        admin = _windows_admin()
    else:
        admin = hasattr(os, "geteuid") and os.geteuid() == 0
    return {"system": platform.system(), "release": platform.release(),
            "machine": platform.machine(), "python": platform.python_version(),
            "is_admin": admin}


def detect_tools() -> list:
    """List known tools on PATH. Only well-behaved tools are asked for a version
    (some, e.g. Sysinternals whois, show an EULA prompt)."""
    out = []
    for name in TOOLS:
        path = shutil.which(name)
        version = ""
        if path and name in ("nmap", "rustscan", "tshark"):
            try:
                p = subprocess.run([path, "--version"], capture_output=True, text=True,
                                   timeout=5, creationflags=_NO_WINDOW)
                lines = (p.stdout or p.stderr).splitlines()
                version = lines[0][:120] if lines else ""
            except Exception:
                pass
        out.append({"name": name, "installed": bool(path), "path": path or "", "version": version})
    return out


# =============================================================================
# VALIDATION
# =============================================================================
_BAD_CHARS = set(";|&`$<>\"' \n\r\t\\")


def validate_target(target: str) -> str:
    """Accept one IP, CIDR, IP range (a.b.c.d-e) or hostname. Reject anything that
    could be mistaken for a command-line option or shell syntax."""
    target = (target or "").strip()
    if not target:
        raise ValueError("Target is required.")
    if len(target) > 253:
        raise ValueError("Target is too long.")
    if target.startswith("-"):
        raise ValueError("Invalid target: must not start with '-'.")
    if any(c in _BAD_CHARS for c in target):
        raise ValueError("Invalid target. Enter one IP, CIDR, or hostname.")
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    if not all(c.isalnum() or c in ".-_:/" for c in target):
        raise ValueError("Invalid hostname.")
    return target


def validate_host(target: str) -> str:
    """Stricter: a single hostname or IP address (no CIDR / URL)."""
    target = validate_target(target)
    if "/" in target:
        raise ValueError("Enter a single hostname or IP address.")
    return target


# =============================================================================
# ENGINE: network discovery
# =============================================================================
def interfaces() -> list:
    rows = []
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET:
                    rows.append({"interface": name, "ip": a.address, "netmask": a.netmask})
    except Exception:
        pass
    return rows


def local_networks() -> list:
    out = []
    for x in interfaces():
        try:
            net = ipaddress.ip_network(f"{x['ip']}/{x['netmask']}", strict=False)
            out.append({**x, "cidr": str(net), "network": str(net.network_address),
                        "broadcast": str(net.broadcast_address)})
        except Exception:
            pass
    return out


def _probe_host(addr: str, ports, timeout: float):
    for port in ports:
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((addr, port))
            return port
        except OSError:
            pass
        finally:
            s.close()
    return None


def discover(cidr: str, timeout: float = 0.6, max_hosts: int = 1024, cancel_event=None,
             workers: int = 64) -> list:
    """Bounded TCP-connect reachability discovery (no raw sockets / admin needed)."""
    from concurrent.futures import ThreadPoolExecutor
    net = ipaddress.ip_network(validate_target(cidr), strict=False)
    if net.num_addresses > max_hosts:
        raise ValueError(f"Range has {net.num_addresses} addresses; limit is {max_hosts}. "
                         "Narrow the CIDR.")
    ports = (80, 443, 22, 445, 3389, 135, 8080)
    hosts = [str(h) for h in (net.hosts() if net.num_addresses > 2 else net)]

    def work(addr):
        if cancel_event is not None and cancel_event.is_set():
            return None
        port = _probe_host(addr, ports, timeout)
        if port is None:
            return None
        try:
            name = socket.gethostbyaddr(addr)[0]
        except Exception:
            name = ""
        return {"ip": addr, "hostname": name, "status": "online",
                "discovery": "tcp-connect", "evidence_ports": [port]}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(work, hosts))
    if cancel_event is not None and cancel_event.is_set():
        raise RuntimeError("Discovery cancelled.")
    return [r for r in results if r]


# =============================================================================
# ENGINE: DNS
# =============================================================================
def dns_lookup(domain: str, record: str = "A") -> list:
    domain = (domain or "").strip().rstrip(".")
    if not domain or any(c in domain for c in " /\\;|"):
        raise ValueError("Enter a valid domain.")
    record = record.upper()
    try:
        import dns.resolver
    except ImportError:
        if record in ("A", "AAAA"):
            fam = socket.AF_INET if record == "A" else socket.AF_INET6
            return [{"name": domain, "type": record, "value": x[4][0]}
                    for x in socket.getaddrinfo(domain, None, fam)]
        raise RuntimeError("Install dnspython for this DNS record type.")
    answers = dns.resolver.resolve(domain, record, lifetime=5)
    return [{"name": domain, "type": record, "value": str(x)} for x in answers]


# =============================================================================
# ENGINE: Nmap
# =============================================================================
NMAP_PROFILES = {
    "Quick Scan": ["-sn"],
    "Standard Scan": ["-sV", "--top-ports", "1000"],
    "Full Port Scan": ["-p-", "-T3"],
    "Service Detection": ["-sV", "-sC"],
    "OS Detection": ["-O", "-sV"],
    "Security Assessment": ["-sV", "--script", "safe"],
}


def build_nmap_command(target: str, profile: str = "Standard Scan", extra_ports=None) -> list:
    target = validate_target(target)
    nmap = shutil.which("nmap")
    if not nmap:
        raise RuntimeError("Nmap is not installed. Install Nmap and make sure it is on PATH.")
    args = list(NMAP_PROFILES.get(profile, ["-sV"]))
    if extra_ports:
        if not re.fullmatch(r"[0-9,\-]+", str(extra_ports)):
            raise ValueError("Ports may only contain digits, commas and hyphens.")
        args = ["-Pn", "-p", str(extra_ports), "-sV"]
    return [nmap, *args, "-oX", "-", "--", target]


def _run_process(cmd, timeout, cancel_event=None) -> tuple:
    """Run a subprocess with deadlock-free output capture, timeout and cancellation."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, errors="replace", creationflags=_NO_WINDOW)
    started = time.monotonic()
    try:
        while True:
            try:
                stdout, stderr = proc.communicate(timeout=0.3)
                return proc.returncode, stdout, stderr
            except subprocess.TimeoutExpired:
                pass
            if cancel_event is not None and cancel_event.is_set():
                proc.kill()
                proc.communicate()
                raise RuntimeError("Scan cancelled.")
            if time.monotonic() - started > timeout:
                proc.kill()
                proc.communicate()
                raise TimeoutError(f"Command exceeded the {timeout}-second timeout.")
    finally:
        if proc.poll() is None:
            proc.kill()


def parse_nmap_xml(xml_text: str) -> list:
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall("host"):
        addr = None
        for a in h.findall("address"):
            if a.get("addrtype", "").startswith("ipv"):
                addr = a
                break
        if addr is None:
            addr = h.find("address")
        ports = []
        for p in h.findall("./ports/port"):
            state, svc = p.find("state"), p.find("service")
            ports.append({
                "port": int(p.get("portid")), "protocol": p.get("protocol"),
                "state": state.get("state") if state is not None else "unknown",
                "service": svc.get("name", "") if svc is not None else "",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else ""})
        hn = h.find("./hostnames/hostname")
        st = h.find("status")
        os_match = h.find("./os/osmatch")
        hosts.append({
            "ip": addr.get("addr") if addr is not None else "",
            "hostname": hn.get("name", "") if hn is not None else "",
            "status": st.get("state") if st is not None else "unknown",
            "os": os_match.get("name", "") if os_match is not None else "",
            "ports": ports})
    return hosts


def nmap_scan(target, profile="Standard Scan", extra_ports=None, timeout=900,
              cancel_event=None) -> list:
    cmd = build_nmap_command(target, profile, extra_ports)
    code, stdout, stderr = _run_process(cmd, timeout, cancel_event)
    if code not in (0, 1) or not stdout.strip():
        raise RuntimeError((stderr or "Nmap failed.").strip()[-2000:])
    hosts = parse_nmap_xml(stdout)
    for h in hosts:
        h["scan_profile"] = "Custom ports" if extra_ports else profile
    return hosts


# =============================================================================
# ENGINE: RustScan (fast port discovery, optional)
# =============================================================================
def rustscan_available() -> bool:
    return shutil.which("rustscan") is not None


def _extract_nmap_xml(text: str) -> str:
    start = text.find("<?xml")
    if start < 0:
        start = text.find("<nmaprun")
    end = text.rfind("</nmaprun>")
    if start < 0 or end < 0:
        raise RuntimeError("RustScan/Nmap did not return parseable XML.")
    return text[start:end + len("</nmaprun>")]


def scan_fast(target, timeout=120, batch_size=4500, port_timeout_ms=700,
              service_detection=False, cancel_event=None) -> dict:
    target = validate_target(target)
    rustscan, nmap = shutil.which("rustscan"), shutil.which("nmap")
    if not rustscan:
        if not nmap:
            raise RuntimeError("Neither RustScan nor Nmap is installed.")
        hosts = nmap_scan(target, "Standard Scan" if service_detection else "Quick Scan",
                          timeout=timeout, cancel_event=cancel_event)
        return {"engine": "Nmap fallback", "fast_discovery": False,
                "service_detection": service_detection, "hosts": hosts,
                "note": "RustScan is not installed; Nmap fallback was used."}
    if not nmap:
        raise RuntimeError("RustScan is installed, but Nmap is required for XML results.")
    nmap_args = ["-n", "-Pn", "-sT"] + (["-sV"] if service_detection else []) + ["-oX", "-"]
    cmd = [rustscan, "-a", target, "--no-banner", "-b", str(int(batch_size)),
           "-t", str(int(port_timeout_ms)), "--", *nmap_args]
    started = time.monotonic()
    code, stdout, stderr = _run_process(cmd, timeout, cancel_event)
    elapsed = round(time.monotonic() - started, 2)
    if code not in (0, 1):
        raise RuntimeError((stderr or stdout or "RustScan failed.").strip()[-2000:])
    try:
        hosts = parse_nmap_xml(_extract_nmap_xml(stdout or ""))
    except RuntimeError:
        hosts = []  # RustScan skips Nmap entirely when no ports are open
    for h in hosts:
        h["scan_profile"] = "rustscan"
    open_ports = sum(1 for h in hosts for p in h["ports"] if p["state"] == "open")
    return {"engine": "RustScan + Nmap", "fast_discovery": True,
            "service_detection": bool(service_detection), "elapsed_seconds": elapsed,
            "open_port_count": open_ports, "hosts": hosts,
            "note": ("RustScan discovery with Nmap service fingerprinting." if service_detection
                     else "Fast TCP discovery; service/version fingerprinting skipped.")}


# =============================================================================
# ENGINE: exposure correlation (heuristic, NOT CVE verification)
# =============================================================================
RISK_PORTS = {
    21: ("FTP exposed", "Review anonymous access and enforce encrypted file transfer."),
    23: ("Telnet exposed", "Disable Telnet; use SSH."),
    445: ("SMB exposed", "Restrict SMB to trusted networks and patch hosts."),
    3389: ("RDP exposed", "Restrict RDP, require MFA and use a VPN or gateway."),
    5900: ("VNC exposed", "Restrict remote desktop exposure and enforce strong authentication."),
    6379: ("Redis exposed", "Bind to trusted interfaces and require authentication."),
    9200: ("Elasticsearch exposed", "Require authentication and restrict network access."),
    139: ("NetBIOS exposed", "Block NetBIOS from untrusted networks; disable if unused."),
    1433: ("MSSQL exposed", "Restrict database access to application hosts only."),
    3306: ("MySQL exposed", "Bind to localhost or a private interface; restrict by firewall."),
    5432: ("PostgreSQL exposed", "Restrict listen_addresses and pg_hba.conf to trusted hosts."),
    5985: ("WinRM exposed", "Restrict WinRM to management hosts and require HTTPS."),
    27017: ("MongoDB exposed", "Enable authentication and bind to trusted interfaces."),
}
HIGH_RISK_PORTS = (23, 445, 6379, 9200, 27017)


def assess_host(host: dict) -> list:
    findings = []
    for p in host.get("ports", []):
        if p.get("state") != "open":
            continue
        port = p.get("port")
        if port in RISK_PORTS:
            title, fix = RISK_PORTS[port]
            findings.append({
                "title": title, "port": port,
                "severity": "High" if port in HIGH_RISK_PORTS else "Medium",
                "confidence": "potential",
                "evidence": f"TCP/{port} open; service={p.get('service') or 'unknown'}",
                "recommendation": fix, "cve": None})
    return findings


def build_topology(devices: list, gateway=None) -> dict:
    seen, nodes = set(), []
    for d in devices:
        ip = d.get("ip")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        nodes.append({"id": ip, "label": d.get("hostname") or ip,
                      "kind": "gateway" if gateway and ip == gateway else "host",
                      "ip": ip, "status": d.get("status", "unknown")})
    edges = []
    if gateway and gateway in seen:
        edges = [{"source": gateway, "target": n["id"],
                  "evidence": "same discovered subnet; gateway relation is assumed"}
                 for n in nodes if n["id"] != gateway]
    return {"nodes": nodes, "edges": edges}


# =============================================================================
# ENGINE: web / TLS / local utilities
# =============================================================================
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS", "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options", "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy"}


def _normalize_https_url(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("Enter a URL or hostname.")
    if target.lower().startswith("http://"):
        raise ValueError("Only HTTPS is supported for passive checks. Use https://.")
    url = target if target.lower().startswith("https://") else "https://" + target
    p = urlparse(url)
    if not p.hostname:
        raise ValueError("Invalid URL.")
    return url


def http_headers(target: str, timeout: float = 8.0) -> dict:
    """Passive GET; HTTP error statuses (403/404...) are still valid evidence."""
    url = _normalize_https_url(target)
    req = urllib.request.Request(url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as err:
        resp = err
    with resp:
        headers = dict(resp.headers.items())
        status = getattr(resp, "status", None) or resp.getcode()
        final_url = resp.geturl()
    lowered = {k.lower(): v for k, v in headers.items()}
    checks = [{"tool": "HTTP security headers", "item": label,
               "status": "Present" if key in lowered else "Not detected",
               "evidence": lowered.get(key, "Header absent in response")}
              for key, label in SECURITY_HEADERS.items()]
    return {"url": url, "final_url": final_url, "http_status": status,
            "headers": headers, "checks": checks}


def tls_info(target: str, timeout: float = 6.0) -> dict:
    p = urlparse(target if "://" in target else "https://" + target)
    host, port = p.hostname, p.port or 443
    if not host:
        raise ValueError("Invalid host.")
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            return {"host": host, "port": port,
                    "subject": cert.get("subject"), "issuer": cert.get("issuer"),
                    "notBefore": cert.get("notBefore"), "notAfter": cert.get("notAfter"),
                    "subjectAltName": cert.get("subjectAltName"),
                    "tls_version": tls.version(), "cipher": tls.cipher()}


def hash_text(text: str) -> dict:
    data = text.encode("utf-8")
    return {a: hashlib.new(a, data).hexdigest() for a in ("md5", "sha1", "sha256", "sha512")}


def hash_file(path, algorithms=("md5", "sha1", "sha256", "sha512")) -> dict:
    p = Path(path)
    if not p.is_file():
        raise ValueError("Select a valid file path.")
    hs = {a: hashlib.new(a) for a in algorithms}
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            for h in hs.values():
                h.update(chunk)
    return {a: h.hexdigest() for a, h in hs.items()}


def identify_hash(value: str) -> dict:
    s = value.strip().lower()
    table = [(32, "MD5 / NTLM"), (40, "SHA-1"), (56, "SHA-224"), (64, "SHA-256"),
             (96, "SHA-384"), (128, "SHA-512")]
    guesses = [n for length, n in table if len(s) == length and re.fullmatch(r"[0-9a-f]+", s)]
    return {"length": len(s), "possible_algorithms": guesses or ["Unknown / unsupported format"],
            "note": "Length-based identification is ambiguous."}


def check_integrity(path, expected: str) -> dict:
    expected = (expected or "").strip().lower()
    algo = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}.get(len(expected), "sha256")
    actual = hash_file(path, (algo,))[algo]
    return {"file": str(path), "algorithm": algo, "actual": actual,
            "expected": expected or "(none supplied)",
            "match": (actual == expected) if expected else None}


def file_info(path) -> dict:
    p = Path(path)
    if not p.is_file():
        raise ValueError("Enter an existing file path.")
    st = p.stat()
    with p.open("rb") as f:
        head = f.read(16)
    magic = {b"MZ": "Windows executable (PE)", b"\x7fELF": "ELF executable", b"%PDF": "PDF document",
             b"PK\x03\x04": "ZIP-based archive/Office file", b"\x89PNG": "PNG image",
             b"\xff\xd8\xff": "JPEG image", b"GIF8": "GIF image",
             b"\xd4\xc3\xb2\xa1": "PCAP (little-endian)", b"\xa1\xb2\xc3\xd4": "PCAP (big-endian)",
             b"\x0a\x0d\x0d\x0a": "PCAPNG"}
    ftype = next((v for k, v in magic.items() if head.startswith(k)), "Unknown / text / other")
    return {"name": p.name, "path": str(p.resolve()), "size_bytes": st.st_size,
            "modified_utc": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            "created_or_changed_utc": datetime.fromtimestamp(st.st_ctime, timezone.utc).isoformat(),
            "detected_type": ftype, **hash_file(p, ("md5", "sha256"))}


def analyze_log(path, limit: int = 500) -> dict:
    p = Path(path)
    if not p.is_file():
        raise ValueError("Enter a log file path.")
    pat = re.compile(r"\b(error|critical|fatal|warning|failed|failure|denied)\b", re.I)
    counts, hits, total = {}, [], 0
    with p.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            total += 1
            m = pat.search(line)
            if m:
                k = m.group(1).lower()
                counts[k] = counts.get(k, 0) + 1
                if len(hits) < limit:
                    hits.append(line.rstrip()[:400])
    return {"lines": total, "keyword_counts": counts, "matches": hits}


def password_strength(pw: str) -> dict:
    checks = {"lowercase": bool(re.search(r"[a-z]", pw)), "uppercase": bool(re.search(r"[A-Z]", pw)),
              "digit": bool(re.search(r"\d", pw)), "symbol": bool(re.search(r"[^A-Za-z0-9]", pw)),
              "length>=12": len(pw) >= 12}
    score = sum(checks.values())
    label = ["Very weak", "Very weak", "Weak", "Fair", "Good", "Strong"][score]
    return {"score": f"{score}/5", "rating": label, "checks": checks,
            "note": "Basic local heuristic only; the password is never stored."}


def pcap_summary(path, limit: int = 300) -> dict:
    exe = shutil.which("tshark")
    if not exe:
        raise RuntimeError("TShark is not installed. Install Wireshark/TShark and retry.")
    if not Path(path).is_file():
        raise ValueError("Enter an existing PCAP file.")
    code, out, err = _run_process(
        [exe, "-r", str(path), "-T", "fields", "-e", "frame.number", "-e", "ip.src",
         "-e", "ip.dst", "-e", "frame.protocols", "-e", "frame.len"], 120)
    if code:
        raise RuntimeError(err.strip()[-2000:] or "TShark failed.")
    lines = out.splitlines()
    protos = {}
    for ln in lines:
        parts = ln.split("\t")
        if len(parts) >= 4 and parts[3]:
            top = parts[3].split(":")[-1]
            protos[top] = protos.get(top, 0) + 1
    return {"packets": len(lines), "top_protocols": dict(sorted(protos.items(), key=lambda kv: -kv[1])[:15]),
            "first_packets": lines[:limit]}


def run_simple_tool(kind: str, target: str) -> str:
    """WHOIS / traceroute through the OS utility. Arguments are a list (no shell)."""
    target = validate_host(target)
    if kind == "whois":
        exe = shutil.which("whois")
        if not exe:
            raise RuntimeError("whois is not installed (optional).")
        args = [exe, target]
    else:
        exe = shutil.which("tracert" if os.name == "nt" else "traceroute")
        if not exe:
            raise RuntimeError("traceroute/tracert is not available.")
        args = [exe, "-d", "-h", "15", target] if os.name == "nt" else [exe, "-m", "15", target]
    code, out, err = _run_process(args, 120)
    return (out or err or "(no output)")[:20000]


def connections_snapshot(limit: int = 500) -> list:
    import psutil
    rows = []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        raise RuntimeError("Access denied. Run with elevated privileges to list connections.")
    for c in conns[:limit]:
        rows.append({"local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                     "remote": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                     "status": c.status, "pid": c.pid or ""})
    return rows


def bandwidth_snapshot() -> dict:
    import psutil
    return {k: v._asdict() for k, v in psutil.net_io_counters(pernic=True).items()}


# =============================================================================
# ENGINE: category assessment (bounded, non-destructive checks)
# =============================================================================
ASSESSMENT_CATEGORIES = [
    "NETWORK INTELLIGENCE", "RECONNAISSANCE", "VULNERABILITY MANAGEMENT",
    "TRAFFIC ANALYSIS", "WEB SECURITY", "WIRELESS SECURITY",
    "SECURITY UTILITIES", "DIGITAL FORENSICS", "SYSTEM",
]


def run_category_assessment(category: str, target: str, cancel_event=None) -> dict:
    target = (target or "").strip()
    if category not in ASSESSMENT_CATEGORIES:
        raise ValueError(f"Category assessment is not supported: {category}")
    local_only = category in ("TRAFFIC ANALYSIS", "WIRELESS SECURITY", "SECURITY UTILITIES",
                              "DIGITAL FORENSICS", "SYSTEM")
    if not target and not local_only:
        raise ValueError("Enter a target first.")
    if target and not local_only:
        if category == "WEB SECURITY":
            _normalize_https_url(target)
        else:
            validate_target(target)

    report = {"category": category, "target": target or "(local system)",
              "started_at": utcnow(), "results": [], "skipped": [], "summary": ""}

    def add(tool, result, status="Completed"):
        report["results"].append({"tool": tool, "status": status, "result": result})

    def skip(tool, reason):
        report["skipped"].append({"tool": tool, "reason": reason})

    if category == "NETWORK INTELLIGENCE":
        if rustscan_available():
            res = scan_fast(target, service_detection=False, cancel_event=cancel_event)
            add(f"Fast TCP discovery ({res.get('engine')})", res)
        else:
            add("Nmap service scan", nmap_scan(target, "Standard Scan", cancel_event=cancel_event))
            skip("RustScan fast discovery", "RustScan is not installed; Nmap Standard Scan was used instead.")

    elif category == "RECONNAISSANCE":
        host = urlparse(target).hostname if "://" in target else target
        for record in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                add(f"DNS {record}", dns_lookup(host, record))
            except Exception as exc:
                skip(f"DNS {record}", f"{type(exc).__name__}: {exc}")
        if shutil.which("whois"):
            try:
                add("WHOIS", run_simple_tool("whois", host))
            except Exception as exc:
                skip("WHOIS", str(exc))
        else:
            skip("WHOIS", "whois executable not installed")
        skip("Subdomain discovery / OSINT", "No passive data-source integration configured; not simulated.")

    elif category == "VULNERABILITY MANAGEMENT":
        hosts = nmap_scan(target, "Security Assessment", cancel_event=cancel_event)
        add("Nmap safe service/script assessment", {"hosts": hosts})
        findings = [{**f, "target": h.get("ip") or target} for h in hosts for f in assess_host(h)]
        add("Evidence-based exposure correlation", findings)
        skip("CVE verification", "No CVE feed or authenticated scanner configured; port matches are not CVE proof.")

    elif category == "WEB SECURITY":
        web = http_headers(target)
        add("HTTPS response and security headers", web)
        try:
            add("TLS certificate inspection", tls_info(web["url"]))
        except Exception as exc:
            skip("TLS certificate inspection", f"{type(exc).__name__}: {exc}")
        skip("Directory brute force / active ZAP", "Not run automatically; needs explicit separate scope.")

    elif category == "TRAFFIC ANALYSIS":
        try:
            add("Local active connection monitor", connections_snapshot())
        except Exception as exc:
            skip("Local active connection monitor", str(exc))
        try:
            add("Local interface counters", bandwidth_snapshot())
        except Exception as exc:
            skip("Local interface counters", str(exc))
        skip("Remote traffic capture", "Packet capture is local-interface/PCAP based, not a remote probe.")

    elif category == "WIRELESS SECURITY":
        add("Local network interfaces", interfaces())
        skip("Wi-Fi / Bluetooth audit", "Needs OS-specific adapter tools and hardware; no synthetic results.")

    elif category == "SECURITY UTILITIES":
        skip("Hashing / file integrity / password utilities",
             "These operate on local files or input, not a remote target. Use the Toolbox page.")

    elif category == "DIGITAL FORENSICS":
        skip("File, log and PCAP forensics",
             "These require selected local evidence files. Use the Toolbox page.")

    elif category == "SYSTEM":
        add("Platform", detect_platform())
        add("Installed security tool inventory", detect_tools())

    report["finished_at"] = utcnow()
    report["summary"] = (f"{len(report['results'])} tool operation(s) completed; "
                         f"{len(report['skipped'])} skipped or unavailable.")
    return report


# =============================================================================
# REPORT EXPORT
# =============================================================================
def export_json(path, payload):
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str),
                          encoding="utf-8")


def export_html(path, title, payload):
    body = html.escape(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    doc = (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
           "<style>body{font-family:Segoe UI,Arial;background:#0b0f14;color:#e8edf3;margin:32px}"
           "h1{color:#19c6b4}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#111a23;"
           "padding:20px;border-radius:8px}</style></head><body>"
           f"<h1>{html.escape(title)}</h1><p>Generated by {APP_NAME} on {utcnow()}</p>"
           f"<pre>{body}</pre></body></html>")
    Path(path).write_text(doc, encoding="utf-8")


def export_csv(path, rows):
    rows = list(rows)
    keys = sorted({k for row in rows for k in row}) or ["message"]
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        w = csv.DictWriter(handle, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        if rows:
            w.writerows(rows)
        else:
            w.writerow({"message": "No records available"})


def export_pdf(path, title, payload):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted, Table, TableStyle

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="NSHeading", parent=styles["Heading2"],
                              textColor=colors.HexColor("#087f78"), spaceBefore=10, spaceAfter=5))
    styles.add(ParagraphStyle(name="NSBody", parent=styles["BodyText"], fontSize=8, leading=10))
    styles.add(ParagraphStyle(name="NSCode", parent=styles["Code"], fontName="Courier",
                              fontSize=6.5, leading=8, wordWrap="CJK"))
    cell = ParagraphStyle(name="NSCell", parent=styles["BodyText"], fontSize=6, leading=7.5, wordWrap="CJK")
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm)
    story = [Paragraph(html.escape(title), styles["Title"]),
             Paragraph(f"{APP_NAME} security assessment report - {utcnow()}", styles["NSBody"]),
             Spacer(1, 8)]

    def section(name, value):
        story.append(Paragraph(html.escape(str(name).replace("_", " ").title()), styles["NSHeading"]))
        if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
            cols = list(dict.fromkeys(k for r in value[:80] for k in r))[:5]
            data = [[Paragraph(html.escape(c), cell) for c in cols]]
            for row in value[:80]:
                data.append([Paragraph(html.escape(str(row.get(c, ""))[:160]), cell) for c in cols])
            t = Table(data, repeatRows=1, colWidths=[(A4[0] - 32 * mm) / len(cols)] * len(cols))
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d8eceb")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#aab4bf")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f5f7")])]))
            story.append(t)
            if len(value) > 80:
                story.append(Paragraph(f"... {len(value) - 80} more record(s) in the JSON export.", styles["NSBody"]))
        elif value in ([], {}, None):
            story.append(Paragraph("No records.", styles["NSBody"]))
        else:
            story.append(Preformatted(json.dumps(value, indent=2, ensure_ascii=False, default=str)[:15000],
                                      styles["NSCode"]))

    def summary_block(es):
        grade = es.get("overall_grade", "–")
        gcol = {"A": "#1E9E5A", "B": "#1E9E5A", "C": "#B7791F", "D": "#B7791F", "F": "#C0392B"}.get(grade, "#5F6E7C")
        score = es.get("overall_score")
        story.append(Paragraph("Executive Summary", styles["NSHeading"]))
        story.append(Paragraph(f"<font size=30 color='{gcol}'><b>{html.escape(str(grade))}</b></font>"
                               f"&nbsp;&nbsp;<font size=11>Overall security grade"
                               f"{'' if score is None else f' ({score}/100)'}</font>", styles["NSBody"]))
        story.append(Spacer(1, 6))
        labels = [("hosts_in_inventory", "Hosts in inventory"), ("potential_findings", "Potential findings"),
                  ("attack_paths", "Attack paths identified"), ("top_attack_paths", "Top attack paths"),
                  ("worst_hosts", "Lowest-graded hosts"), ("rogue_devices", "Rogue devices"),
                  ("missing_trusted_devices", "Trusted devices not seen"), ("note", "Note")]
        rows = []
        for key, label in labels:
            v = es.get(key)
            text = "<br/>".join(html.escape(str(x)) for x in v) if isinstance(v, list) else html.escape(str(v))
            rows.append([Paragraph(f"<b>{label}</b>", cell), Paragraph(text or "none", cell)])
        t = Table(rows, colWidths=[45 * mm, A4[0] - 32 * mm - 45 * mm])
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#aab4bf")),
                               ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef3f6")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)

    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in ("generated_by", "generated_at"):
                continue
            if key == "executive_summary" and isinstance(value, dict):
                summary_block(value)
                continue
            if key == "records" and isinstance(value, dict):
                for bucket, rows in value.items():
                    section(bucket, rows)
            else:
                section(key, value)
    else:
        story.append(Preformatted(json.dumps(payload, indent=2, default=str)[:50000], styles["NSCode"]))
    doc.build(story)


# =============================================================================
# OPTIONAL NATIVE C HELPER (ctypes)
# =============================================================================
C_DIR = ROOT / "backend"


def native_library_path() -> Path:
    return C_DIR / "bindings" / ("netscope.dll" if os.name == "nt" else "libnetscope.so")


def build_native() -> Path:
    src, inc, out = C_DIR / "c_src" / "netscope.c", C_DIR / "c_include", native_library_path()
    if not src.exists():
        raise FileNotFoundError("backend/c_src/netscope.c not found.")
    if not shutil.which("gcc"):
        raise RuntimeError("gcc not found on PATH (the C helper is optional).")
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["gcc", "-shared", "-O2", f"-I{inc}", str(src), "-o", str(out)]
    if os.name != "nt":
        cmd.insert(2, "-fPIC")
    subprocess.run(cmd, check=True)
    return out


def load_native():
    import ctypes
    path = native_library_path()
    if not path.exists():
        return None
    lib = ctypes.CDLL(str(path))
    lib.ns_add.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.ns_add.restype = ctypes.c_int
    lib.ns_version.restype = ctypes.c_char_p
    return lib


# =============================================================================
# ENGINE: inventory, time machine (snapshots), baseline / rogue devices
# =============================================================================
def _is_up(host: dict) -> bool:
    return host.get("status") in ("up", "online")


def _port_key_int(key: str) -> int:
    return int(str(key).split("/")[0])


def make_snapshot(label: str, target: str, hosts: list, ports_known=None, complete=True) -> dict:
    """Normalize a scan result into a point-in-time snapshot.
    complete=False means absent hosts must NOT be treated as gone (e.g. RustScan)."""
    out = []
    for h in hosts:
        if not _is_up(h) or not h.get("ip"):
            continue
        known = (h.get("scan_profile") != "Quick Scan") if ports_known is None else ports_known
        services = {}
        for p in h.get("ports", []):
            if p.get("state") == "open":
                desc = " ".join(x for x in (p.get("service"), p.get("product"), p.get("version")) if x)
                services[f"{p['port']}/{p.get('protocol') or 'tcp'}"] = desc
        entry = {"ip": h["ip"], "hostname": h.get("hostname", ""), "os": h.get("os", ""),
                 "ports_known": bool(known),
                 "open": sorted(services, key=_port_key_int), "services": services}
        if h.get("scan_profile") == "Custom ports":  # partial scan: only these ports were examined
            entry["scanned"] = sorted({f"{p['port']}/{p.get('protocol') or 'tcp'}" for p in h.get("ports", [])})
            entry["ports_known"] = True
        out.append(entry)
    return {"label": label, "target": target, "complete": bool(complete), "hosts": out}


def _target_network(target: str):
    try:
        net = ipaddress.ip_network((target or "").strip(), strict=False)
    except ValueError:
        return None
    return net if net.num_addresses > 1 else None


def apply_snapshot(inventory: dict, snap: dict) -> dict:
    inv = {ip: dict(h) for ip, h in inventory.items()}
    seen = {h["ip"] for h in snap["hosts"]}
    net = _target_network(snap.get("target", "")) if snap.get("complete", True) else None
    if net is not None:
        for ip in list(inv):
            try:
                inside = ipaddress.ip_address(ip) in net
            except ValueError:
                inside = False
            if inside and ip not in seen:
                del inv[ip]
    for h in snap["hosts"]:
        old, new = inv.get(h["ip"]), dict(h)
        if old and h.get("scanned"):
            scanned = set(h["scanned"])
            services = {k: v for k, v in old.get("services", {}).items() if k not in scanned}
            services.update(h["services"])
            new["services"], new["open"] = services, sorted(services, key=_port_key_int)
            new.pop("scanned", None)
        elif old and not h["ports_known"]:
            new["open"], new["services"], new["ports_known"] = old["open"], old["services"], old["ports_known"]
        if old and not new.get("hostname"):
            new["hostname"] = old.get("hostname", "")
        inv[h["ip"]] = new
    return inv


def inventory_upto(snapshots: list, index: int) -> dict:
    inv = {}
    for snap in snapshots[:max(0, index + 1)]:
        inv = apply_snapshot(inv, snap)
    return inv


def diff_inventories(old: dict, new: dict) -> dict:
    opened, closed = {}, {}
    for ip in set(old) & set(new):
        if old[ip].get("ports_known") and new[ip].get("ports_known"):
            o, n = set(old[ip]["open"]), set(new[ip]["open"])
            if n - o:
                opened[ip] = sorted(n - o, key=_port_key_int)
            if o - n:
                closed[ip] = sorted(o - n, key=_port_key_int)
    return {"new_hosts": sorted(set(new) - set(old)), "gone_hosts": sorted(set(old) - set(new)),
            "opened_ports": opened, "closed_ports": closed}


def default_local_cidr():
    nets = [n for n in local_networks() if not n["ip"].startswith("127.")]
    return nets[0]["cidr"] if nets else None


def load_baseline(store):
    return store.read_json("baseline.json", None)


def save_baseline(store, inventory: dict) -> dict:
    data = {"created_at": utcnow(), "ips": sorted(inventory),
            "hostnames": {ip: h.get("hostname", "") for ip, h in inventory.items()}}
    store.write_json("baseline.json", data)
    return data


def baseline_alerts(inventory: dict, baseline) -> dict:
    if not baseline:
        return {"has_baseline": False, "rogue": [], "missing": []}
    trusted = set(baseline.get("ips", []))
    return {"has_baseline": True, "created_at": baseline.get("created_at", ""),
            "rogue": sorted(set(inventory) - trusted), "missing": sorted(trusted - set(inventory))}


# =============================================================================
# ENGINE: security grade
# =============================================================================
GRADE_BANDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def letter_for(score) -> str:
    if score is None:
        return "?"
    return next(letter for floor, letter in GRADE_BANDS if score >= floor)


def _scan_host(host: dict) -> dict:
    ports = []
    for key, desc in host.get("services", {}).items():
        ports.append({"port": _port_key_int(key), "state": "open", "service": (desc or "").split(" ")[0]})
    return {"ip": host.get("ip", ""), "ports": ports}


def host_score(host: dict):
    """0-100 exposure score (higher is better). None when ports were never scanned."""
    if not host.get("ports_known"):
        return None, []
    findings = assess_host(_scan_host(host))
    ports = {_port_key_int(k) for k in host.get("open", [])}
    penalty = sum(15 if f["severity"] == "High" else 8 for f in findings)
    penalty += min(10, len([p for p in ports if p not in RISK_PORTS]))
    if 80 in ports and 443 not in ports:
        penalty += 3
    return max(0, 100 - penalty), findings


def security_grade(inventory: dict) -> dict:
    rows = []
    for ip, h in inventory.items():
        score, findings = host_score(h)
        rows.append({"ip": ip, "hostname": h.get("hostname", ""), "score": score, "grade": letter_for(score),
                     "open_ports": len(h.get("open", [])), "findings": len(findings)})
    rows.sort(key=lambda r: (r["score"] is None, r["score"] if r["score"] is not None else 0, r["ip"]))
    scored = [r["score"] for r in rows if r["score"] is not None]
    overall = round(0.6 * (sum(scored) / len(scored)) + 0.4 * min(scored)) if scored else None
    return {"overall_score": overall, "overall_grade": letter_for(overall) if scored else "–", "hosts": rows}


# =============================================================================
# ENGINE: attack path stories (hypothetical chains from exposure, not exploitation)
# =============================================================================
REMOTE_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5985: "WinRM"}
SMB_PORTS = {445: "SMB", 139: "NetBIOS"}
DB_PORTS = {1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch"}
WEB_PORTS = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-alt", 8443: "HTTPS-alt"}
WEAK_BY_DEFAULT = {6379, 9200, 27017}
_PORT_NAMES = {**REMOTE_PORTS, **SMB_PORTS, **DB_PORTS, **WEB_PORTS, 21: "FTP"}


def _open_ints(host: dict) -> set:
    return {_port_key_int(k) for k in host.get("open", [])}


def _path_severity(score: int) -> str:
    return "Critical" if score >= 85 else "High" if score >= 70 else "Medium" if score >= 50 else "Low"


def _same_subnet(a: str, b: str) -> bool:
    try:
        x, y = ipaddress.ip_address(a), ipaddress.ip_address(b)
    except ValueError:
        return False
    if x.version != 4 or y.version != 4:
        return False
    return y in ipaddress.ip_network(f"{a}/24", strict=False)


def compute_attack_paths(inventory: dict, limit: int = 12) -> list:
    known = {ip: h for ip, h in inventory.items() if h.get("ports_known")}
    paths, seen_ids = [], set()

    def step(ip, port, note):
        host = known.get(ip, {})
        return {"host": ip, "name": host.get("hostname") or ip, "port": port,
                "service": _PORT_NAMES.get(port, "?"), "note": note}

    def add(title, score, steps, narrative, mitigation):
        score = max(0, min(100, int(score)))
        pid = hashlib.sha1((title + "|" + ",".join(f"{s['host']}:{s['port']}" for s in steps)).encode()).hexdigest()[:10]
        if pid in seen_ids:
            return
        seen_ids.add(pid)
        paths.append({"id": pid, "title": title, "score": score, "severity": _path_severity(score),
                      "hosts": list(dict.fromkeys(s["host"] for s in steps)), "steps": steps,
                      "narrative": narrative + " (Hypothetical chain based on exposed services; nothing was exploited.)",
                      "mitigation": mitigation})

    for ip, h in sorted(known.items()):
        ports, name = _open_ints(h), h.get("hostname") or ip
        remote, smb = sorted(ports & set(REMOTE_PORTS)), sorted(ports & set(SMB_PORTS))
        web, db = sorted(ports & set(WEB_PORTS)), sorted(ports & set(DB_PORTS))
        if remote and smb:
            r, sm = remote[0], smb[0]
            add(f"Remote login to file-share lateral movement on {name}", 68 + (10 if set(remote) & {23, 3389, 5900} else 0) + (10 if 445 in smb else 0),
                [step(ip, r, f"{REMOTE_PORTS[r]} lets an attacker try stolen or guessed credentials"),
                 step(ip, sm, f"{SMB_PORTS[sm]} then exposes shares and enables spreading to other machines")],
                f"{name} exposes {REMOTE_PORTS[r]} and {SMB_PORTS[sm]}. A single compromised password could give "
                "remote access and then access to shared files or other systems.",
                ["Restrict remote access to a VPN or management subnet", "Require MFA / key-based login",
                 "Block SMB from untrusted networks"])
        if web and db:
            w, d = web[0], db[0]
            add(f"Web foothold to data-store access on {name}", 72 + (10 if set(db) & WEAK_BY_DEFAULT else 0),
                [step(ip, w, "A flaw in the web application gives an attacker a first foothold"),
                 step(ip, d, f"{DB_PORTS[d]} on the same host holds the data the foothold can reach")],
                f"{name} runs a web service and {DB_PORTS[d]} together. A web vulnerability could be chained to "
                "read or change stored data.",
                ["Bind the database to localhost or a private interface", "Enforce authentication on the data store",
                 "Patch and harden the web application"])
        clear = [p for p in (21, 23) if p in ports] + ([80] if 80 in ports and 443 not in ports else [])
        if clear:
            c = clear[0]
            add(f"Cleartext credential capture on {name}", 50 + (10 if c in (21, 23) else 0),
                [step(ip, c, f"{_PORT_NAMES.get(c, '?')} sends logins unencrypted")],
                f"{name} offers {_PORT_NAMES.get(c, '?')} without encryption. Anyone able to observe traffic on "
                "the network path could read credentials.",
                ["Replace with SSH / SFTP / HTTPS", "Disable the legacy service if unused"])

    entry_priority = [23, 3389, 5900, 5985, 22, 8080, 80, 443, 8443]
    entries = {ip: sorted(_open_ints(h) & (set(REMOTE_PORTS) | set(WEB_PORTS)),
                          key=lambda p: entry_priority.index(p) if p in entry_priority else 99)
               for ip, h in known.items()}
    for tip, h in sorted(known.items()):
        for tport in sorted(_open_ints(h) & (set(SMB_PORTS) | set(DB_PORTS))):
            cands = [(eip, ep[0]) for eip, ep in entries.items() if ep and eip != tip and _same_subnet(eip, tip)]
            if not cands:
                continue
            eip, eport = min(cands, key=lambda c: entry_priority.index(c[1]) if c[1] in entry_priority else 99)
            score = 60 + (15 if tport in WEAK_BY_DEFAULT or tport == 445 else 8) + (10 if eport in (23, 3389, 5900) else 0)
            en, tn = known[eip].get("hostname") or eip, h.get("hostname") or tip
            add(f"Pivot from {en} to {tn}", score,
                [step(eip, eport, f"{_PORT_NAMES.get(eport, '?')} is the entry point into the network"),
                 step(tip, tport, f"{_PORT_NAMES.get(tport, '?')} on a neighbouring host becomes the next target")],
                f"If {en} is compromised via {_PORT_NAMES.get(eport, '?')}, the attacker is on the same subnet as "
                f"{tn}, which exposes {_PORT_NAMES.get(tport, '?')}.",
                ["Segment the network so servers are not reachable from exposed hosts",
                 "Restrict the target service to the hosts that need it"])
    paths.sort(key=lambda p: (-p["score"], p["title"]))
    return paths[:limit]


# =============================================================================
# ENGINE: fix-it playbooks (commands are shown as text; NetScope never runs them)
# =============================================================================
_PLAYBOOKS = {
    21: ("Disable or replace FTP", ["Stop-Service FTPSVC; Set-Service FTPSVC -StartupType Disabled"],
         ["sudo systemctl disable --now vsftpd", "sudo ufw deny 21/tcp"]),
    22: ("Harden SSH", ["Set-Service sshd -StartupType Manual   # only if SSH is not needed"],
         ["sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
          "sudo systemctl reload ssh"]),
    23: ("Disable Telnet", ["dism /online /Disable-Feature /FeatureName:TelnetServer"],
         ["sudo systemctl disable --now telnet.socket", "sudo ufw deny 23/tcp"]),
    80: ("Redirect HTTP to HTTPS", ["# Configure an HTTP->HTTPS redirect in IIS URL Rewrite"],
         ["# nginx: return 301 https://$host$request_uri;", "# apache: Redirect permanent / https://your.host/"]),
    139: ("Block NetBIOS", ['New-NetFirewallRule -DisplayName "Block NetBIOS 139" -Direction Inbound -Protocol TCP -LocalPort 139 -Action Block'],
          ["sudo ufw deny 139/tcp"]),
    445: ("Restrict SMB", ["Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                           'New-NetFirewallRule -DisplayName "Block SMB inbound" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block   # allow trusted subnets first'],
         ["sudo ufw allow from <TRUSTED_SUBNET> to any port 445 proto tcp", "sudo ufw deny 445/tcp"]),
    3389: ("Secure RDP", ["Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
                          'Set-NetFirewallRule -DisplayGroup "Remote Desktop" -RemoteAddress <TRUSTED_SUBNET>'],
          ["sudo ufw deny 3389/tcp"]),
    5900: ("Restrict VNC", ['New-NetFirewallRule -DisplayName "Block VNC 5900" -Direction Inbound -Protocol TCP -LocalPort 5900 -Action Block'],
           ["sudo ufw deny 5900/tcp", "# tunnel VNC through SSH instead"]),
    5985: ("Restrict WinRM", ['Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -RemoteAddress <TRUSTED_SUBNET>'], []),
    6379: ("Secure Redis", ["# Edit redis.conf: bind 127.0.0.1 and set requirepass"],
           ["sudo sed -i 's/^# *bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf", "sudo systemctl restart redis-server"]),
    9200: ("Secure Elasticsearch", ["# elasticsearch.yml: network.host: 127.0.0.1 and enable xpack.security"],
           ["sudo sed -i 's/^#\\?network.host:.*/network.host: 127.0.0.1/' /etc/elasticsearch/elasticsearch.yml",
            "sudo systemctl restart elasticsearch"]),
    27017: ("Secure MongoDB", ["# mongod.cfg: net.bindIp: 127.0.0.1 and security.authorization: enabled"],
            ["sudo sed -i 's/^ *bindIp:.*/  bindIp: 127.0.0.1/' /etc/mongod.conf", "sudo systemctl restart mongod"]),
}


def playbook_for_port(port: int, host: str = "<HOST>") -> dict:
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("Port must be 1-65535.")
    title, win, lin = _PLAYBOOKS.get(port, (f"Close or restrict TCP/{port}", [
        f'New-NetFirewallRule -DisplayName "Block TCP {port}" -Direction Inbound -Protocol TCP -LocalPort {port} -Action Block'],
        [f"sudo ufw deny {port}/tcp"]))
    if not lin and port in _PLAYBOOKS:
        lin = [f"sudo ufw deny {port}/tcp"]
    return {"port": port, "title": title, "windows": win, "linux": lin,
            "verify": f"nmap -Pn -p {port} {host}",
            "warning": "Review before running: closing a port can interrupt services or lock you out of remote access."}


def format_playbook(pb: dict) -> str:
    out = [pb["title"], "", pb["warning"], "", "Windows (PowerShell, as Administrator):"]
    out += [f"  {c}" for c in pb["windows"]] or ["  (no Windows-specific step)"]
    out += ["", "Linux:"] + ([f"  {c}" for c in pb["linux"]] or ["  (no Linux-specific step)"])
    out += ["", "Verify afterwards:", f"  {pb['verify']}"]
    return "\n".join(out)


# =============================================================================
# ENGINE: insights, executive summary
# =============================================================================
def compute_insights(store) -> dict:
    snaps = store.read("snapshots")
    inv, trend = {}, []
    for snap in snaps:
        inv = apply_snapshot(inv, snap)
        g = security_grade(inv)
        trend.append({"label": snap.get("label", ""), "target": snap.get("target", ""),
                      "time": snap.get("created_at", ""), "hosts": len(inv),
                      "score": g["overall_score"], "grade": g["overall_grade"]})
    grade = security_grade(inv)
    return {"snapshots": snaps, "inventory": inv, "grade": grade, "trend": trend,
            "paths": compute_attack_paths(inv),
            "alerts": baseline_alerts(inv, load_baseline(store)),
            "findings": sum(h["findings"] for h in grade["hosts"])}


def executive_summary(ins: dict) -> dict:
    g = ins["grade"]
    return {"overall_grade": g["overall_grade"], "overall_score": g["overall_score"],
            "hosts_in_inventory": len(ins["inventory"]), "potential_findings": ins["findings"],
            "attack_paths": len(ins["paths"]),
            "top_attack_paths": [f"{p['severity']}: {p['title']} ({', '.join(p['hosts'])})" for p in ins["paths"][:3]],
            "rogue_devices": ins["alerts"]["rogue"], "missing_trusted_devices": ins["alerts"]["missing"],
            "worst_hosts": [f"{h['ip']} grade {h['grade']}" for h in g["hosts"][:3] if h["score"] is not None],
            "note": "Findings are exposure heuristics, not CVE verification."}


# =============================================================================
# ENGINE: tamper-evident report seals (hash chain + local HMAC key)
# =============================================================================
def _seal_key(store) -> bytes:
    path = store.base / "report.key"
    if not path.exists():
        path.write_text(os.urandom(32).hex(), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return bytes.fromhex(path.read_text(encoding="utf-8").strip())


def _chain_hash(prev: str, digest: str, ts: str, name: str) -> str:
    return hashlib.sha256(f"{prev}|{digest}|{ts}|{name}".encode("utf-8")).hexdigest()


def _sign(store, chain_hash: str) -> str:
    return hmac.new(_seal_key(store), chain_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def seal_file(store, path) -> dict:
    p = Path(path)
    digest = hash_file(p, ("sha256",))["sha256"]
    chain = store.read("report_chain")
    prev = chain[-1]["chain_hash"] if chain else "0" * 64
    ts = utcnow()
    ch = _chain_hash(prev, digest, ts, p.name)
    rec = {"file": p.name, "sha256": digest, "prev_hash": prev, "chain_hash": ch,
           "sealed_at": ts, "signature": _sign(store, ch)}
    store.append("report_chain", rec)
    sidecar = p.with_name(p.name + ".seal.json")
    sidecar.write_text(json.dumps({**rec, "app": f"{APP_NAME} {APP_VERSION}"}, indent=2), encoding="utf-8")
    return rec


def verify_chain(store) -> dict:
    prev, problems, records = "0" * 64, [], store.read("report_chain")
    key_ok = (store.base / "report.key").exists()
    for i, r in enumerate(records, 1):
        if r.get("prev_hash") != prev:
            problems.append(f"seal #{i}: broken link (a seal was removed or reordered)")
        if _chain_hash(r.get("prev_hash", ""), r.get("sha256", ""), r.get("sealed_at", ""), r.get("file", "")) != r.get("chain_hash"):
            problems.append(f"seal #{i}: record was modified")
        elif key_ok and not hmac.compare_digest(_sign(store, r["chain_hash"]), r.get("signature", "")):
            problems.append(f"seal #{i}: signature invalid")
        prev = r.get("chain_hash", "")
    return {"ok": not problems, "seals": len(records), "problems": problems}


def verify_seal(store, path) -> dict:
    p, checks = Path(path), []

    def chk(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    sidecar = p.with_name(p.name + ".seal.json")
    if not p.is_file():
        raise ValueError("Select an existing report file.")
    if not sidecar.is_file():
        chk("Seal file present", False, f"{sidecar.name} not found")
        return {"ok": False, "checks": checks}
    try:
        seal = json.loads(sidecar.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        chk("Seal file readable", False, "invalid JSON")
        return {"ok": False, "checks": checks}
    chk("Seal file present", True, sidecar.name)
    actual = hash_file(p, ("sha256",))["sha256"]
    chk("Report content unchanged", actual == seal.get("sha256"), "SHA-256 matches the sealed value" if actual == seal.get("sha256") else "SHA-256 differs - the file was modified")
    recs = [r for r in store.read("report_chain") if r.get("chain_hash") == seal.get("chain_hash")]
    chk("Seal registered in local chain", bool(recs) and recs[0].get("sha256") == seal.get("sha256"),
        "found" if recs else "not found on this machine")
    chain = verify_chain(store)
    chk("Hash chain intact", chain["ok"], "; ".join(chain["problems"]) or f"{chain['seals']} seal(s) verified")
    return {"ok": all(c["ok"] for c in checks), "checks": checks}


# =============================================================================
# ENGINE: command palette ranking, radar geometry, themes
# =============================================================================
def fuzzy_score(query: str, text: str) -> int:
    q, t = query.strip().lower(), text.lower()
    if not q:
        return 1
    idx = t.find(q)
    if idx == 0:
        return 220
    if idx > 0:
        return max(101, 200 - idx - (len(t) - len(q)) // 4)
    pos, gaps = 0, 0
    for ch in q:
        nxt = t.find(ch, pos)
        if nxt < 0:
            return 0
        gaps += nxt - pos
        pos = nxt + 1
    return max(1, 100 - gaps)


def palette_rank(query: str, entries: list, limit: int = 12) -> list:
    scored = [(fuzzy_score(query, e["title"] + " " + e.get("keywords", "")), i, e) for i, e in enumerate(entries)]
    return [e for s, i, e in sorted((x for x in scored if x[0] > 0), key=lambda x: (-x[0], x[1]))][:limit]


def radar_polar(ip: str, score) -> tuple:
    """Deterministic (angle_degrees, radius_fraction). Lower grade = closer to the centre."""
    angle = (int(hashlib.sha1(ip.encode()).hexdigest()[:8], 16) % 3600) / 10.0
    frac = 0.5 if score is None else 0.28 + 0.62 * (max(0, min(100, score)) / 100.0)
    return angle, frac


THEMES = {
    "dark": dict(bg="#0B0F14", panel="#111A23", panel2="#17232D", side="#111820", border="#263541", text="#E8EDF3",
                 muted="#8D9AAA", accent="#19C6B4", accent_bg="#17343A", hover="#1B2833", button="#1B2A36",
                 button_border="#2A3B49", danger="#E0524D", warn="#E0A33A", ok="#3DBE7A", alt="#121C25",
                 select="#176D69", grid="#25323D"),
    "light": dict(bg="#F3F6F9", panel="#FFFFFF", panel2="#EAF0F5", side="#FFFFFF", border="#D3DCE4", text="#17212B",
                  muted="#5F6E7C", accent="#0A9C8E", accent_bg="#D8F1EE", hover="#E6EEF4", button="#F1F5F9",
                  button_border="#C9D4DE", danger="#C0392B", warn="#B7791F", ok="#1E9E5A", alt="#F6F9FB",
                  select="#B6E4DF", grid="#E1E8EE"),
}

_QSS = Template("""
QWidget{background:$bg;color:$text;font-family:'Segoe UI','Inter','Noto Sans',Arial;font-size:13px}
#sidebar{background:$side;border-right:1px solid $border}
#brand{font-size:24px;font-weight:700;color:$accent;padding:8px;background:transparent}
#muted{color:$muted;font-size:12px;background:transparent}
#pageTitle{font-size:25px;font-weight:650;background:transparent}
#sectionTitle{font-size:15px;font-weight:600;background:transparent}
#alertBanner{background:$danger;color:#FFFFFF;border-radius:6px;padding:9px 12px;font-weight:600}
#okBanner{background:$accent_bg;color:$accent;border-radius:6px;padding:9px 12px;font-weight:600}
QPushButton#navButton{background:transparent;border:0;text-align:left;padding:11px 12px;border-radius:6px;color:$muted}
QPushButton#navButton:hover{background:$hover;color:$text}
QPushButton#navButton:checked{background:$accent_bg;color:$accent;font-weight:600}
QPushButton{background:$button;border:1px solid $button_border;border-radius:6px;padding:8px 13px;color:$text}
QPushButton:hover{border-color:$accent}
QPushButton:disabled{color:$muted;border-color:$border}
QPushButton#danger{border-color:$danger}
QPushButton#primary{background:$accent;color:#06201D;border-color:$accent;font-weight:600}
QLineEdit,QComboBox,QPlainTextEdit,QTableWidget,QListWidget{background:$panel;border:1px solid $border;border-radius:6px;padding:6px;selection-background-color:$select;selection-color:$text}
QComboBox QAbstractItemView{background:$panel;selection-background-color:$select}
QHeaderView::section{background:$panel2;color:$muted;padding:8px;border:0}
QTableWidget{gridline-color:$grid;alternate-background-color:$alt}
QFrame#card{background:$panel;border:1px solid $border;border-radius:8px}
QLabel#cardValue{font-size:26px;font-weight:700;color:$accent;background:transparent}
QLabel#cardLabel{color:$muted;background:transparent}
QProgressBar{background:$panel2;border:0;border-radius:4px;max-height:6px}
QProgressBar::chunk{background:$accent;border-radius:4px}
QSlider::groove:horizontal{height:6px;background:$panel2;border-radius:3px}
QSlider::handle:horizontal{background:$accent;width:18px;margin:-6px 0;border-radius:9px}
QSlider::sub-page:horizontal{background:$accent;border-radius:3px}
QStatusBar{background:$side;color:$muted}
QToolTip{background:$panel;color:$text;border:1px solid $accent}
QDialog{background:$bg}
""")


def build_stylesheet(theme: str = "dark") -> str:
    return _QSS.substitute(THEMES.get(theme, THEMES["dark"]))


def grade_color(letter: str, theme: str = "dark") -> str:
    t = THEMES.get(theme, THEMES["dark"])
    return {"A": t["ok"], "B": t["ok"], "C": t["warn"], "D": t["warn"], "F": t["danger"]}.get(letter, t["muted"])


# =============================================================================
# GUI (PySide6) - imported lazily so engines and --selftest work without Qt
# =============================================================================
def _compact(value, limit=220) -> str:
    text = json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list, tuple)) else str(value)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _summarize_result(result) -> str:
    if isinstance(result, dict) and isinstance(result.get("hosts"), list):
        extra = f" · {result['elapsed_seconds']} s" if result.get("elapsed_seconds") is not None else ""
        return f"{len(result['hosts'])} host(s){extra}"
    if isinstance(result, dict) and "http_status" in result:
        return f"HTTP {result['http_status']}"
    if isinstance(result, list):
        return f"{len(result)} record(s)"
    if isinstance(result, dict):
        return f"{len(result)} field(s)"
    return "Completed"


def _extract_hosts(result) -> list:
    """Return Nmap-style host dicts (with a 'ports' list) from a result, if any."""
    if isinstance(result, dict) and isinstance(result.get("hosts"), list):
        return [h for h in result["hosts"] if isinstance(h, dict)]
    if isinstance(result, list) and result and all(isinstance(h, dict) and "ports" in h for h in result):
        return result
    return []


def run_gui() -> int:
    try:
        from PySide6.QtCore import (Qt, QThread, Signal, QPointF, QRectF, QTimer, QPropertyAnimation,
                                    QVariantAnimation)
        from PySide6.QtGui import QBrush, QColor, QPen, QFont, QPainter, QKeySequence, QShortcut
        from PySide6.QtWidgets import (
            QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QPushButton,
            QStackedWidget, QFrame, QGridLayout, QTableWidget, QTableWidgetItem, QMessageBox,
            QLineEdit, QComboBox, QProgressBar, QPlainTextEdit, QFileDialog, QAbstractItemView,
            QDialog, QListWidget, QSlider, QGraphicsOpacityEffect)
    except ImportError as exc:
        print("PySide6 is not installed. Run:  pip install -r requirements.txt\n", exc)
        return 2

    state = {"theme": "dark"}

    class TaskWorker(QThread):
        succeeded = Signal(object)
        failed = Signal(str)

        def __init__(self, fn):
            super().__init__()
            self.fn = fn  # called as fn(cancel_event)
            self.cancel_event = threading.Event()

        def cancel(self):
            self.cancel_event.set()

        def run(self):
            try:
                self.succeeded.emit(self.fn(self.cancel_event))
            except Exception as exc:  # reported to the UI thread
                self.failed.emit(f"{type(exc).__name__}: {exc}")

    def make_table(headers):
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setStretchLastSection(True)
        t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        return t

    def fill_table(table, rows):
        table.setRowCount(0)
        for values in rows:
            r = table.rowCount()
            table.insertRow(r)
            for c, v in enumerate(values):
                item = QTableWidgetItem(str(v))
                item.setToolTip(str(v)[:2000])
                table.setItem(r, c, item)

    def fill_generic(table, rows):
        """Show a list of dicts with columns derived from the data."""
        if not rows:
            table.setColumnCount(1)
            table.setHorizontalHeaderLabels(["Result"])
            fill_table(table, [["No records."]])
            return
        cols = list(dict.fromkeys(k for r in rows[:200] for k in r))[:8]
        table.setColumnCount(len(cols))
        table.setHorizontalHeaderLabels(cols)
        table.horizontalHeader().setStretchLastSection(True)
        fill_table(table, [[_compact(r.get(c, ""), 160) for c in cols] for r in rows[:2000]])
        table.resizeColumnsToContents()

    class BackgroundMixin:
        """Runs a worker, keeps a strong reference, and cleans it up safely."""
        def _start(self, fn, on_ok, on_err, on_done=None):
            worker = TaskWorker(fn)
            self._worker = worker
            worker.succeeded.connect(on_ok)
            worker.failed.connect(on_err)

            def finished():
                worker.wait()
                worker.deleteLater()
                if self._worker is worker:
                    self._worker = None
                if on_done:
                    on_done()
            worker.finished.connect(finished)
            worker.start()
            return worker

        def is_busy(self):
            return getattr(self, "_worker", None) is not None

        def stop_worker(self):
            w = getattr(self, "_worker", None)
            if w is not None:
                w.cancel()
                w.wait(5000)

    def card(title, value):
        f = QFrame()
        f.setObjectName("card")
        lay = QVBoxLayout(f)
        a, b = QLabel(title), QLabel(str(value))
        a.setObjectName("cardLabel")
        b.setObjectName("cardValue")
        lay.addWidget(a)
        lay.addWidget(b)
        if isinstance(value, int) and value > 0:  # count-up animation (owned by the card, dies with it)
            anim = QVariantAnimation(f)
            anim.setStartValue(0)
            anim.setEndValue(int(value))
            anim.setDuration(600)

            def update(v, label=b):
                try:
                    label.setText(str(int(v)))
                except RuntimeError:
                    pass
            anim.valueChanged.connect(update)
            anim.start()
        return f

    def record_scan_results(store, source_label, target, result):
        """Persist hosts and potential findings from any scan result. Returns host count."""
        hosts = _extract_hosts(result)
        for host in hosts:
            store.append("scans", {**host, "target": target, "profile": source_label})
            for finding in assess_host(host):
                store.append("vulnerabilities", {**finding, "target": host.get("ip") or target})
        if hosts:
            complete = not any(h.get("scan_profile") == "rustscan" for h in hosts)
            store.append("snapshots", make_snapshot(source_label, target, hosts, complete=complete))
        return len(hosts)

    def record_discovery(store, target, devices):
        for d in devices:
            store.append("devices", d)
        if devices:
            store.append("snapshots", make_snapshot("Network Discovery", target, devices, ports_known=False))

    # ------------------------------------------------------------------ Dashboard
    class Dashboard(QWidget, BackgroundMixin):
        def __init__(self, store, navigate):
            super().__init__()
            self.store, self.navigate, self._worker = store, navigate, None
            lay = QVBoxLayout(self)
            lay.setContentsMargins(28, 24, 28, 24)
            lay.setSpacing(12)
            top = QHBoxLayout()
            title = QLabel("Security Overview")
            title.setObjectName("pageTitle")
            top.addWidget(title)
            top.addStretch()
            for name, fn in (("Refresh", self.refresh), ("Generate report", lambda: navigate("Reports"))):
                b = QPushButton(name)
                b.clicked.connect(lambda checked=False, f=fn: f())
                top.addWidget(b)
            lay.addLayout(top)
            desc = QLabel("Choose a category and an authorized target. NetScope runs the supported checks "
                          "for that category and combines the results. Unsupported or local-only operations "
                          "are reported as skipped, never simulated. Individual utilities are in the Toolbox.")
            desc.setObjectName("muted")
            desc.setWordWrap(True)
            lay.addWidget(desc)

            row = QHBoxLayout()
            self.target = QLineEdit()
            self.target.setPlaceholderText("Authorized target: hostname, IP or CIDR (URL for WEB SECURITY)")
            self.target.returnPressed.connect(self.start_assessment)
            self.category = QComboBox()
            self.category.addItems(ASSESSMENT_CATEGORIES)
            self.run_btn = QPushButton("Run Category Assessment")
            self.run_btn.clicked.connect(lambda checked=False: self.start_assessment())
            self.cancel_btn = QPushButton("Cancel")
            self.cancel_btn.setObjectName("danger")
            self.cancel_btn.setEnabled(False)
            self.cancel_btn.clicked.connect(lambda checked=False: self.cancel())
            row.addWidget(self.target, 4)
            row.addWidget(self.category, 2)
            row.addWidget(self.run_btn)
            row.addWidget(self.cancel_btn)
            lay.addLayout(row)

            self.status = QLabel("Ready for an authorized assessment.")
            self.status.setObjectName("muted")
            lay.addWidget(self.status)
            self.busy = QProgressBar()
            self.busy.setRange(0, 0)
            self.busy.setTextVisible(False)
            self.busy.hide()
            lay.addWidget(self.busy)
            self.alert = QLabel()
            self.alert.setObjectName("alertBanner")
            self.alert.setWordWrap(True)
            self.alert.hide()
            lay.addWidget(self.alert)
            self.hint = QLabel()
            self.hint.setObjectName("muted")
            self.hint.setWordWrap(True)
            lay.addWidget(self.hint)
            self.cards = QGridLayout()
            self.cards.setSpacing(12)
            lay.addLayout(self.cards)
            lay.addWidget(QLabel("Latest category assessment"))
            self.table = make_table(["Tool", "Status", "Result summary", "Evidence / details"])
            lay.addWidget(self.table, 3)
            lay.addWidget(QLabel("Recent activity"))
            self.recent = make_table(["Activity", "Target / detail", "Timestamp"])
            lay.addWidget(self.recent, 2)
            self.refresh()

        def refresh(self):
            while self.cards.count():
                item = self.cards.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            ins = compute_insights(self.store)
            g, alerts = ins["grade"], ins["alerts"]
            gf = QFrame()
            gf.setObjectName("card")
            gl = QVBoxLayout(gf)
            ga, gb = QLabel("Security grade"), QLabel(
                f"{g['overall_grade']}  ·  {g['overall_score']}" if g["overall_score"] is not None else "–")
            ga.setObjectName("cardLabel")
            gb.setObjectName("cardValue")
            gb.setStyleSheet(f"font-size:26px;font-weight:700;background:transparent;"
                             f"color:{grade_color(g['overall_grade'], state['theme'])}")
            gl.addWidget(ga)
            gl.addWidget(gb)
            self.cards.addWidget(gf, 0, 0)
            metrics = [("Assessment runs", self.store.count("assessment_runs")),
                       ("Hosts in inventory", len(ins["inventory"])),
                       ("Potential findings", ins["findings"]),
                       ("Attack paths", len(ins["paths"])),
                       ("Rogue devices", len(alerts["rogue"]))]
            for i, (h, v) in enumerate(metrics, 1):
                self.cards.addWidget(card(h, v), 0, i)
            if alerts["rogue"]:
                self.alert.setText("⚠ ROGUE DEVICE ALARM: " + ", ".join(alerts["rogue"][:8]) +
                                   (" …" if len(alerts["rogue"]) > 8 else "") + " is not in your trusted baseline.")
                self.alert.show()
            else:
                self.alert.hide()
            self.hint.setText("" if alerts["has_baseline"] else
                              "Tip: open Time Machine and trust your current devices to enable rogue-device alarms.")
            hist = list(reversed(self.store.read("history")[-10:]))
            fill_table(self.recent, [[r.get("action", "Activity"), r.get("target", r.get("summary", "—")),
                                      r.get("created_at", "—")] for r in hist])
            self.recent.resizeColumnsToContents()

        def set_busy(self, busy):
            for w in (self.target, self.category, self.run_btn):
                w.setEnabled(not busy)
            self.cancel_btn.setEnabled(busy)
            self.busy.setVisible(busy)
            self.run_btn.setText("⏳ Scan in progress…" if busy else "Run Category Assessment")

        def cancel(self):
            w = self._worker
            if w:
                w.cancel()
                self.status.setText("Cancelling… waiting for the running tool to stop.")

        def start_assessment(self):
            if self.is_busy():
                return
            category, target = self.category.currentText(), self.target.text().strip()
            local_only = category in ("TRAFFIC ANALYSIS", "WIRELESS SECURITY", "SECURITY UTILITIES",
                                      "DIGITAL FORENSICS", "SYSTEM")
            if not target and not local_only:
                QMessageBox.warning(self, "Target required",
                                    "Enter a hostname, IP or CIDR that you own or are explicitly authorized to assess.")
                self.target.setFocus()
                return
            where = target or "this computer"
            ans = QMessageBox.question(
                self, "Confirm authorized assessment",
                f"Run the available {category} checks against {where}?\n\nOnly continue if you have "
                "permission. Unsupported or local-only operations will be reported as skipped.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if ans != QMessageBox.StandardButton.Yes:
                return
            self.set_busy(True)
            self.table.setRowCount(0)
            self.status.setText(f"SCAN IN PROGRESS • {category} • {where} • please wait…")

            def job(cancel_event):
                return run_category_assessment(category, target, cancel_event)
            self._start(job, self.on_success, self.on_error, lambda: self.set_busy(False))

        def on_success(self, report):
            try:
                saved = self.store.append("assessment_runs", report)
                self.store.append("history", {"action": f"{report['category']} assessment",
                                              "target": report["target"], "summary": report["summary"]})
                rows = []
                for item in report["results"]:
                    res = item["result"]
                    self.store.append("assessment_results", {
                        "run_id": saved["id"], "category": report["category"], "target": report["target"],
                        "tool": item["tool"], "status": item["status"], "result": res})
                    record_scan_results(self.store, item["tool"], report["target"], res)
                    rows.append([item["tool"], item["status"], _summarize_result(res), _compact(res, 1800)])
                for item in report["skipped"]:
                    rows.append([item["tool"], "Skipped / unavailable", "Not executed", item["reason"]])
                fill_table(self.table, rows)
                self.table.resizeColumnsToContents()
                self.status.setText(report["summary"] + " Results saved.")
                self.refresh()
            except Exception as exc:
                self.status.setText(f"Assessment finished but results could not be shown: {exc}")
                QMessageBox.warning(self, "Result handling error", str(exc))

        def on_error(self, message):
            self.status.setText("Assessment failed: " + message)
            if "cancelled" not in message.lower():
                QMessageBox.warning(self, "Assessment failed", message)

    # ------------------------------------------------------------------ Toolbox
    def _tool_registry(store):
        """name -> dict(desc, placeholder, options, extra, file, secret, fn(target, option, extra, cancel))"""
        def discover_default(t, o, x, c):
            if not t:
                t = default_local_cidr()
                if not t:
                    raise ValueError("No local IPv4 subnet detected. Enter a CIDR manually.")
            return {"cidr": t, "devices": discover(t, cancel_event=c)}

        def port_scan(t, o, x, c):
            if o == "Fast Scan (RustScan)":
                return scan_fast(t, cancel_event=c)
            return {"hosts": nmap_scan(t, o, cancel_event=c), "engine": "Nmap", "profile": o}

        def evidence(t, o, x, c):
            digest = hash_file(t)["sha256"]
            return store.append("evidence", {"source": str(Path(t).resolve()), "sha256": digest,
                                             "notes": x or "Evidence integrity hash recorded."})

        def need(t):
            if not t:
                raise ValueError("Enter a value first.")
            return t

        return {
            "Network Discovery": dict(desc="TCP-connect host discovery for a CIDR (max 1,024 addresses). Leave empty to use your first local subnet.", ph="CIDR, e.g. 192.168.1.0/24", fn=discover_default),
            "Network Interfaces": dict(desc="Local IPv4 interfaces and subnets.", ph="(no input needed)", fn=lambda t, o, x, c: local_networks()),
            "Port / Service Scan": dict(desc="Nmap profiles or optional RustScan fast discovery. Authorized targets only.", ph="IP, hostname or CIDR", options=list(NMAP_PROFILES) + ["Fast Scan (RustScan)"], option_default="Standard Scan", fn=lambda t, o, x, c: port_scan(need(t), o, x, c)),
            "DNS Lookup": dict(desc="Query DNS records.", ph="example.com", options=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"], fn=lambda t, o, x, c: dns_lookup(need(t), o)),
            "WHOIS Lookup": dict(desc="Uses the local whois executable if installed.", ph="example.com", fn=lambda t, o, x, c: run_simple_tool("whois", need(t))),
            "Traceroute": dict(desc="Uses tracert (Windows) or traceroute.", ph="host or IP", fn=lambda t, o, x, c: run_simple_tool("traceroute", need(t))),
            "HTTP Header Analyzer": dict(desc="Passive HTTPS GET and security-header review.", ph="https://example.com", fn=lambda t, o, x, c: http_headers(need(t))),
            "SSL/TLS Analyzer": dict(desc="Inspect a remote TLS certificate.", ph="example.com or example.com:8443", fn=lambda t, o, x, c: tls_info(need(t))),
            "Hash Generator": dict(desc="MD5/SHA-1/SHA-256/SHA-512 of the text.", ph="Text to hash", fn=lambda t, o, x, c: hash_text(t)),
            "Hash Identifier": dict(desc="Guess hash family by length/format.", ph="Hash value", fn=lambda t, o, x, c: identify_hash(need(t))),
            "File Integrity Checker": dict(desc="Hash a file and compare to an expected digest.", ph="File path", file=True, extra="Expected hash (optional)", fn=lambda t, o, x, c: check_integrity(need(t), x)),
            "File Analysis": dict(desc="Type, size, timestamps and hashes of a file.", ph="File path", file=True, fn=lambda t, o, x, c: file_info(need(t))),
            "Log Analyzer": dict(desc="Count and list error/warning/denied lines.", ph="Log file path", file=True, fn=lambda t, o, x, c: analyze_log(need(t))),
            "PCAP Summary": dict(desc="Summarize a capture with TShark.", ph="PCAP file path", file=True, fn=lambda t, o, x, c: pcap_summary(need(t))),
            "Password Strength": dict(desc="Local heuristic only. Never stored or logged.", ph="Password", secret=True, nolog=True, fn=lambda t, o, x, c: password_strength(t)),
            "Evidence Manager": dict(desc="Record a SHA-256 integrity entry for an evidence file.", ph="Evidence file path", file=True, extra="Notes (optional)", fn=evidence),
            "Connection Monitor": dict(desc="Active local TCP/UDP connections.", ph="(no input needed)", fn=lambda t, o, x, c: connections_snapshot()),
            "Bandwidth Monitor": dict(desc="Per-interface byte counters.", ph="(no input needed)", fn=lambda t, o, x, c: bandwidth_snapshot()),
            "Tool Inventory": dict(desc="Detect installed external security tools.", ph="(no input needed)", fn=lambda t, o, x, c: detect_tools()),
            "Scan Profiles": dict(desc="Built-in Nmap profiles.", ph="(no input needed)", fn=lambda t, o, x, c: NMAP_PROFILES),
        }

    class Toolbox(QWidget, BackgroundMixin):
        def __init__(self, store):
            super().__init__()
            self.store, self._worker = store, None
            self.tools = _tool_registry(store)
            lay = QVBoxLayout(self)
            lay.setContentsMargins(26, 22, 26, 22)
            lay.setSpacing(12)
            t = QLabel("Toolbox")
            t.setObjectName("pageTitle")
            lay.addWidget(t)
            self.desc = QLabel()
            self.desc.setObjectName("muted")
            self.desc.setWordWrap(True)
            lay.addWidget(self.desc)
            row = QHBoxLayout()
            self.tool = QComboBox()
            self.tool.addItems(list(self.tools))
            self.tool.currentTextChanged.connect(self.on_tool)
            self.target = QLineEdit()
            self.target.returnPressed.connect(self.run)
            self.browse = QPushButton("Browse…")
            self.browse.clicked.connect(lambda checked=False: self.pick_file())
            self.option = QComboBox()
            self.run_btn = QPushButton("Run")
            self.run_btn.clicked.connect(lambda checked=False: self.run())
            self.cancel_btn = QPushButton("Cancel")
            self.cancel_btn.setObjectName("danger")
            self.cancel_btn.setEnabled(False)
            self.cancel_btn.clicked.connect(lambda checked=False: self._cancel())
            row.addWidget(self.tool, 2)
            row.addWidget(self.target, 5)
            row.addWidget(self.browse)
            row.addWidget(self.option, 2)
            row.addWidget(self.run_btn)
            row.addWidget(self.cancel_btn)
            lay.addLayout(row)
            self.extra = QLineEdit()
            lay.addWidget(self.extra)
            self.busy = QProgressBar()
            self.busy.setRange(0, 0)
            self.busy.setTextVisible(False)
            self.busy.hide()
            lay.addWidget(self.busy)
            self.table = make_table(["Result"])
            lay.addWidget(self.table, 3)
            self.output = QPlainTextEdit()
            self.output.setReadOnly(True)
            self.output.setPlaceholderText("Results and diagnostics appear here.")
            lay.addWidget(self.output, 2)
            self.on_tool(self.tool.currentText())

        def on_tool(self, name):
            spec = self.tools[name]
            self.desc.setText(spec["desc"])
            self.target.setPlaceholderText(spec["ph"])
            self.target.setEchoMode(QLineEdit.EchoMode.Password if spec.get("secret") else QLineEdit.EchoMode.Normal)
            self.target.clear()
            self.browse.setVisible(bool(spec.get("file")))
            self.option.clear()
            opts = spec.get("options")
            self.option.setVisible(bool(opts))
            if opts:
                self.option.addItems(opts)
                if spec.get("option_default"):
                    self.option.setCurrentText(spec["option_default"])
            self.extra.setVisible(bool(spec.get("extra")))
            self.extra.setPlaceholderText(spec.get("extra", ""))
            self.extra.clear()

        def select_tool(self, name):
            if name in self.tools:
                self.tool.setCurrentText(name)
                self.target.setFocus()

        def pick_file(self):
            path, _ = QFileDialog.getOpenFileName(self, "Select file")
            if path:
                self.target.setText(path)

        def _cancel(self):
            if self._worker:
                self._worker.cancel()

        def set_busy(self, busy):
            for w in (self.tool, self.target, self.option, self.extra, self.run_btn, self.browse):
                w.setEnabled(not busy)
            self.cancel_btn.setEnabled(busy)
            self.busy.setVisible(busy)

        def run(self):
            if self.is_busy():
                return
            name, spec = self.tool.currentText(), self.tools[self.tool.currentText()]
            target, option, extra = self.target.text().strip() if not spec.get("secret") else self.target.text(), \
                self.option.currentText(), self.extra.text().strip()
            self.output.setPlainText(f"Running {name}…")
            self.set_busy(True)

            def job(cancel_event):
                return spec["fn"](target, option, extra, cancel_event)

            def ok(result):
                self.show_result(name, target, spec, result)

            def err(msg):
                self.output.setPlainText("ERROR: " + msg)
                if "cancelled" not in msg.lower():
                    QMessageBox.warning(self, "NetScope", msg)
            self._start(job, ok, err, lambda: self.set_busy(False))

        def show_result(self, name, target, spec, raw):
            result = raw["devices"] if (name == "Network Discovery" and isinstance(raw, dict) and "devices" in raw) else raw
            if isinstance(result, str):
                self.table.setColumnCount(1)
                self.table.setHorizontalHeaderLabels(["Output"])
                fill_table(self.table, [[ln] for ln in result.splitlines()[:2000]])
                self.output.setPlainText(result)
            else:
                text = json.dumps(result, indent=2, ensure_ascii=False, default=str)
                self.output.setPlainText(text)
                rows = None
                if isinstance(result, list) and all(isinstance(r, dict) for r in result):
                    rows = result
                elif isinstance(result, dict) and _extract_hosts(result):
                    rows = [{"ip": h["ip"], "hostname": h["hostname"], "status": h["status"],
                             "open_ports": ", ".join(f"{p['port']}/{p['service'] or '?'}" for p in h["ports"]
                                                     if p["state"] == "open")}
                            for h in _extract_hosts(result)]
                elif isinstance(result, dict):
                    rows = [{"field": k, "value": _compact(v)} for k, v in result.items()]
                fill_generic(self.table, rows or [])
            try:
                if name == "Network Discovery" and isinstance(raw, dict) and "devices" in raw:
                    record_discovery(self.store, raw["cidr"], raw["devices"])
                n_hosts = record_scan_results(self.store, name, target, result)
                if not spec.get("nolog"):
                    self.store.append("history", {"action": name, "target": target or "(local)",
                                                  "summary": _summarize_result(result)})
                if n_hosts:
                    self.output.appendPlainText(f"\n{n_hosts} host result(s) stored.")
            except Exception as exc:
                self.output.appendPlainText(f"\nCould not save history: {exc}")

    # ------------------------------------------------------------------ History
    class HistoryPage(QWidget):
        def __init__(self, store):
            super().__init__()
            self.store = store
            lay = QVBoxLayout(self)
            lay.setContentsMargins(26, 22, 26, 22)
            t = QLabel("Activity History")
            t.setObjectName("pageTitle")
            lay.addWidget(t)
            d = QLabel("Every assessment and tool run saved by NetScope (newest first).")
            d.setObjectName("muted")
            lay.addWidget(d)
            self.table = make_table(["Time (UTC)", "Action", "Target", "Summary"])
            lay.addWidget(self.table)
            self.refresh()

        def refresh(self):
            rows = [[r.get("created_at", "")[:19].replace("T", " "), r.get("action", ""),
                     r.get("target", ""), r.get("summary", "")]
                    for r in reversed(self.store.read("history"))]
            fill_table(self.table, rows or [["", "No activity recorded yet.", "", ""]])
            self.table.resizeColumnsToContents()

    # ------------------------------------------------------------------ Security Posture
    class PosturePage(QWidget, BackgroundMixin):
        def __init__(self, store):
            super().__init__()
            self.store, self._worker, self.rows, self.current = store, None, [], None
            lay = QVBoxLayout(self)
            lay.setContentsMargins(26, 22, 26, 22)
            lay.setSpacing(10)
            t = QLabel("Security Posture")
            t.setObjectName("pageTitle")
            lay.addWidget(t)
            d = QLabel("Grade per host and for the whole network, based on exposed services. Select a finding "
                       "to get fix-it commands you can review and run yourself.")
            d.setObjectName("muted")
            d.setWordWrap(True)
            lay.addWidget(d)
            top = QHBoxLayout()
            self.grade = QLabel("–")
            self.grade.setObjectName("cardValue")
            self.grade.setStyleSheet("font-size:64px;font-weight:800;background:transparent")
            self.grade_note = QLabel("")
            self.grade_note.setObjectName("muted")
            self.grade_note.setWordWrap(True)
            box = QVBoxLayout()
            box.addWidget(self.grade)
            box.addWidget(self.grade_note)
            top.addLayout(box, 1)
            self.trend = make_table(["Time (UTC)", "Scan", "Hosts", "Score", "Grade"])
            top.addWidget(self.trend, 3)
            lay.addLayout(top, 2)
            lay.addWidget(self._title("Hosts (worst first)"))
            self.hosts = make_table(["Host", "Name", "Grade", "Score", "Open ports", "Findings"])
            lay.addWidget(self.hosts, 2)
            lay.addWidget(self._title("Findings and fix-it playbook"))
            row = QHBoxLayout()
            self.findings = make_table(["Host", "Port", "Finding", "Severity"])
            self.findings.itemSelectionChanged.connect(self.on_select)
            row.addWidget(self.findings, 3)
            right = QVBoxLayout()
            self.playbook = QPlainTextEdit()
            self.playbook.setReadOnly(True)
            self.playbook.setPlaceholderText("Select a finding to see commands.")
            right.addWidget(self.playbook, 1)
            btns = QHBoxLayout()
            self.copy_btn = QPushButton("Copy commands")
            self.copy_btn.clicked.connect(lambda checked=False: self.copy())
            self.verify_btn = QPushButton("Re-scan to verify")
            self.verify_btn.setObjectName("primary")
            self.verify_btn.clicked.connect(lambda checked=False: self.verify())
            btns.addWidget(self.copy_btn)
            btns.addWidget(self.verify_btn)
            right.addLayout(btns)
            self.status = QLabel("")
            self.status.setObjectName("muted")
            right.addWidget(self.status)
            row.addLayout(right, 3)
            lay.addLayout(row, 3)

        @staticmethod
        def _title(text):
            lb = QLabel(text)
            lb.setObjectName("sectionTitle")
            return lb

        def refresh(self):
            ins = compute_insights(self.store)
            g = ins["grade"]
            self.grade.setText(g["overall_grade"])
            self.grade.setStyleSheet(f"font-size:64px;font-weight:800;background:transparent;"
                                     f"color:{grade_color(g['overall_grade'], state['theme'])}")
            self.grade_note.setText(
                "No scanned hosts yet. Run a port scan from the Toolbox or Dashboard." if g["overall_score"] is None
                else f"Network score {g['overall_score']}/100 across {sum(1 for h in g['hosts'] if h['score'] is not None)} "
                     f"scanned host(s). Worst-case hosts weigh heavily in the score.")
            fill_table(self.trend, [[(t["time"] or "")[:19].replace("T", " "), t["label"], t["hosts"],
                                     "" if t["score"] is None else t["score"], t["grade"]]
                                    for t in reversed(ins["trend"])])
            fill_table(self.hosts, [[h["ip"], h["hostname"], h["grade"], "" if h["score"] is None else h["score"],
                                     h["open_ports"], h["findings"]] for h in g["hosts"]])
            self.rows = []
            frows = []
            for ip, host in sorted(ins["inventory"].items()):
                score, findings = host_score(host)
                for f in findings:
                    self.rows.append((ip, f["port"]))
                    frows.append([ip, f["port"], f["title"], f["severity"]])
            fill_table(self.findings, frows or [["", "", "No findings - nothing risky detected on scanned hosts.", ""]])
            for tbl in (self.trend, self.hosts, self.findings):
                tbl.resizeColumnsToContents()
            self.playbook.setPlainText("")
            self.current = None

        def on_select(self):
            row = self.findings.currentRow()
            if 0 <= row < len(self.rows):
                ip, port = self.rows[row]
                pb = playbook_for_port(port, ip)
                self.current = (ip, port, pb)
                self.playbook.setPlainText(format_playbook(pb))

        def copy(self):
            if not self.current:
                QMessageBox.information(self, "NetScope", "Select a finding first.")
                return
            pb = self.current[2]
            QApplication.clipboard().setText("\n".join(pb["windows"] + [""] + pb["linux"]))
            self.status.setText("Commands copied. NetScope never runs them for you.")

        def verify(self):
            if not self.current or self.is_busy():
                if not self.current:
                    QMessageBox.information(self, "NetScope", "Select a finding first.")
                return
            ip, port, _ = self.current
            self.verify_btn.setEnabled(False)
            self.status.setText(f"Re-scanning {ip} port {port}…")

            def job(cancel_event):
                return nmap_scan(ip, extra_ports=str(port), timeout=120, cancel_event=cancel_event)

            def ok(hosts):
                record_scan_results(self.store, "Verify fix", ip, hosts)
                state_ = next((p["state"] for h in hosts for p in h["ports"] if p["port"] == port), "closed")
                self.store.append("history", {"action": "Verify fix", "target": f"{ip}:{port}", "summary": state_})
                self.refresh()
                self.status.setText(f"✔ Port {port} on {ip} is now {state_}." if state_ != "open"
                                    else f"✖ Port {port} on {ip} is still open.")

            def err(msg):
                self.status.setText("Verification failed: " + msg)

            self._start(job, ok, err, lambda: self.verify_btn.setEnabled(True))

    # ------------------------------------------------------------------ Attack Paths
    class PathsPage(QWidget):
        def __init__(self, store, show_on_radar):
            super().__init__()
            self.store, self.show_on_radar, self.paths = store, show_on_radar, []
            lay = QVBoxLayout(self)
            lay.setContentsMargins(26, 22, 26, 22)
            lay.setSpacing(10)
            t = QLabel("Attack Paths")
            t.setObjectName("pageTitle")
            lay.addWidget(t)
            d = QLabel("Plain-language stories that chain exposed services into how an attacker could move. "
                       "These are hypothetical, based on what is exposed. Nothing is exploited.")
            d.setObjectName("muted")
            d.setWordWrap(True)
            lay.addWidget(d)
            self.table = make_table(["Score", "Severity", "Path", "Hosts"])
            self.table.itemSelectionChanged.connect(self.on_select)
            lay.addWidget(self.table, 2)
            self.detail = QPlainTextEdit()
            self.detail.setReadOnly(True)
            self.detail.setPlaceholderText("Select a path to read its story and how to break the chain.")
            lay.addWidget(self.detail, 3)
            btn = QPushButton("Show on radar")
            btn.setObjectName("primary")
            btn.clicked.connect(lambda checked=False: self.radar())
            lay.addWidget(btn)

        def refresh(self):
            self.paths = compute_attack_paths(inventory_upto(self.store.read("snapshots"), 10 ** 9))
            fill_table(self.table, [[p["score"], p["severity"], p["title"], ", ".join(p["hosts"])] for p in self.paths]
                       or [["", "", "No attack paths found. Scan hosts to build the picture.", ""]])
            self.table.resizeColumnsToContents()
            self.detail.setPlainText("")

        def selected(self):
            row = self.table.currentRow()
            return self.paths[row] if 0 <= row < len(self.paths) else None

        def on_select(self):
            p = self.selected()
            if not p:
                return
            lines = [f"{p['title']}  -  {p['severity']} ({p['score']}/100)", "", p["narrative"], "", "Steps:"]
            for i, s in enumerate(p["steps"], 1):
                lines.append(f"  {i}. {s['name']} : {s['port']}/{s['service']} - {s['note']}")
            lines += ["", "How to break the chain:"] + [f"  - {m}" for m in p["mitigation"]]
            self.detail.setPlainText("\n".join(lines))

        def radar(self):
            p = self.selected()
            if not p:
                QMessageBox.information(self, "NetScope", "Select a path first.")
                return
            self.show_on_radar(p)

    # ------------------------------------------------------------------ Time Machine
    class TimeMachinePage(QWidget):
        def __init__(self, store, on_change):
            super().__init__()
            self.store, self.on_change, self.snaps = store, on_change, []
            lay = QVBoxLayout(self)
            lay.setContentsMargins(26, 22, 26, 22)
            lay.setSpacing(10)
            t = QLabel("Time Machine")
            t.setObjectName("pageTitle")
            lay.addWidget(t)
            d = QLabel("Replay your network across saved scans: see which hosts appeared or vanished and which "
                       "ports opened or closed. Set a trusted baseline to get rogue-device alarms.")
            d.setObjectName("muted")
            d.setWordWrap(True)
            lay.addWidget(d)
            row = QHBoxLayout()
            self.play = QPushButton("▶ Play")
            self.play.clicked.connect(lambda checked=False: self.toggle_play())
            self.slider = QSlider(Qt.Orientation.Horizontal)
            self.slider.valueChanged.connect(self.show_at)
            row.addWidget(self.play)
            row.addWidget(self.slider, 1)
            lay.addLayout(row)
            self.caption = QLabel("No snapshots yet. Run a discovery or scan first.")
            self.caption.setObjectName("sectionTitle")
            lay.addWidget(self.caption)
            mid = QHBoxLayout()
            self.diff = QPlainTextEdit()
            self.diff.setReadOnly(True)
            mid.addWidget(self.diff, 2)
            self.inv = make_table(["Host", "Name", "Grade", "Open ports"])
            mid.addWidget(self.inv, 3)
            lay.addLayout(mid, 3)
            lay.addWidget(self._title("Trusted baseline / rogue devices"))
            brow = QHBoxLayout()
            self.base_info = QLabel("")
            self.base_info.setObjectName("muted")
            self.base_info.setWordWrap(True)
            self.trust = QPushButton("Trust all current devices")
            self.trust.setObjectName("primary")
            self.trust.clicked.connect(lambda checked=False: self.set_baseline())
            brow.addWidget(self.base_info, 1)
            brow.addWidget(self.trust)
            lay.addLayout(brow)
            self.timer = QTimer(self)
            self.timer.setInterval(900)
            self.timer.timeout.connect(self.advance)

        @staticmethod
        def _title(text):
            lb = QLabel(text)
            lb.setObjectName("sectionTitle")
            return lb

        def hideEvent(self, event):
            self.timer.stop()
            self.play.setText("▶ Play")
            super().hideEvent(event)

        def refresh(self):
            self.snaps = self.store.read("snapshots")
            n = len(self.snaps)
            self.slider.blockSignals(True)
            self.slider.setRange(0, max(0, n - 1))
            self.slider.setValue(max(0, n - 1))
            self.slider.blockSignals(False)
            self.slider.setEnabled(n > 1)
            self.play.setEnabled(n > 1)
            self.show_at(max(0, n - 1))
            self.update_baseline()

        def update_baseline(self):
            ins = compute_insights(self.store)
            a = ins["alerts"]
            if not a["has_baseline"]:
                self.base_info.setText("No baseline set. Trusting your current devices lets NetScope alarm on "
                                       "any new, unknown device.")
            else:
                self.base_info.setText(
                    f"Baseline from {a['created_at'][:19].replace('T', ' ')} UTC.  Rogue devices: "
                    f"{', '.join(a['rogue']) or 'none'}.  Trusted but not seen: {', '.join(a['missing']) or 'none'}.")

        def show_at(self, k):
            n = len(self.snaps)
            if n == 0:
                self.diff.setPlainText("")
                fill_table(self.inv, [])
                return
            k = max(0, min(int(k), n - 1))
            snap = self.snaps[k]
            now, before = inventory_upto(self.snaps, k), inventory_upto(self.snaps, k - 1) if k else {}
            diff = diff_inventories(before, now)
            self.caption.setText(f"Snapshot {k + 1}/{n} · {(snap.get('created_at') or '')[:19].replace('T', ' ')} UTC · "
                                 f"{snap.get('label', '')} → {snap.get('target', '')}")
            lines = []
            lines += [f"+ new host      {ip}" for ip in diff["new_hosts"]]
            lines += [f"- host gone     {ip}" for ip in diff["gone_hosts"]]
            lines += [f"▲ opened        {ip}: {', '.join(p)}" for ip, p in diff["opened_ports"].items()]
            lines += [f"▼ closed        {ip}: {', '.join(p)}" for ip, p in diff["closed_ports"].items()]
            self.diff.setPlainText("\n".join(lines) or ("Baseline snapshot: first view of the network." if k == 0
                                                         else "No changes compared with the previous snapshot."))
            grades = {h["ip"]: h["grade"] for h in security_grade(now)["hosts"]}
            fill_table(self.inv, [[ip, h.get("hostname", ""), grades.get(ip, "?"),
                                   ", ".join(h["open"]) if h.get("ports_known") else "(not port-scanned)"]
                                  for ip, h in sorted(now.items())])
            self.inv.resizeColumnsToContents()

        def advance(self):
            if self.slider.value() >= self.slider.maximum():
                self.slider.setValue(0)
            else:
                self.slider.setValue(self.slider.value() + 1)

        def toggle_play(self):
            if self.timer.isActive():
                self.timer.stop()
                self.play.setText("▶ Play")
            else:
                self.slider.setValue(0)
                self.timer.start()
                self.play.setText("❚❚ Pause")

        def set_baseline(self):
            inv = inventory_upto(self.store.read("snapshots"), 10 ** 9)
            if not inv:
                QMessageBox.information(self, "NetScope", "No devices recorded yet. Run Network Discovery first.")
                return
            ans = QMessageBox.question(self, "Set trusted baseline",
                                       f"Mark all {len(inv)} current device(s) as trusted? Anything new later "
                                       "will raise a rogue-device alarm.",
                                       QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                       QMessageBox.StandardButton.No)
            if ans != QMessageBox.StandardButton.Yes:
                return
            save_baseline(self.store, inv)
            self.store.append("history", {"action": "Baseline set", "target": f"{len(inv)} device(s)",
                                          "summary": "Trusted baseline saved"})
            self.update_baseline()
            self.on_change()

    # ------------------------------------------------------------------ Network Radar
    class RadarCanvas(QWidget):
        hostSelected = Signal(str)

        def __init__(self):
            super().__init__()
            self.setMouseTracking(True)
            self.setMinimumSize(520, 420)
            self.sweep, self.t, self.nodes, self.paths = 0.0, 0.0, [], []
            self.show_paths, self.highlight_path, self.selected = True, None, None
            self.theme = "dark"
            self.timer = QTimer(self)
            self.timer.setInterval(40)
            self.timer.timeout.connect(self._tick)

        def showEvent(self, event):
            self.timer.start()
            super().showEvent(event)

        def hideEvent(self, event):
            self.timer.stop()
            super().hideEvent(event)

        def set_theme(self, name):
            self.theme = name
            self.update()

        def set_data(self, ins):
            grades = {h["ip"]: h for h in ins["grade"]["hosts"]}
            rogue = set(ins["alerts"]["rogue"])
            nodes = []
            for ip, h in ins["inventory"].items():
                g = grades.get(ip, {"score": None, "grade": "?"})
                angle, frac = radar_polar(ip, g["score"])
                nodes.append({"ip": ip, "label": h.get("hostname") or ip, "score": g["score"], "grade": g["grade"],
                              "angle": angle, "frac": frac, "rogue": ip in rogue, "open": list(h.get("open", [])),
                              "phase": (angle % 7) / 7.0})
            self.nodes, self.paths = nodes, ins["paths"]
            self.update()

        def _tick(self):
            self.sweep = (self.sweep + 2.2) % 360
            self.t += 0.04
            self.update()

        def _geom(self):
            w, h = self.width(), self.height()
            return w / 2.0, h / 2.0, max(60.0, min(w, h) / 2.0 - 34.0)

        def _pos(self, n):
            import math
            cx, cy, radius = self._geom()
            a = math.radians(n["angle"])
            return QPointF(cx + n["frac"] * radius * math.cos(a), cy + n["frac"] * radius * math.sin(a))

        def _nearest(self, pos):
            best, best_d = None, 16.0
            for n in self.nodes:
                p = self._pos(n)
                d = ((p.x() - pos.x()) ** 2 + (p.y() - pos.y()) ** 2) ** 0.5
                if d < best_d:
                    best, best_d = n, d
            return best

        def mouseMoveEvent(self, event):
            n = self._nearest(event.position())
            if n:
                self.setToolTip(f"{n['ip']}  {n['label'] if n['label'] != n['ip'] else ''}\nGrade {n['grade']}"
                                f"{'' if n['score'] is None else ' (' + str(n['score']) + ')'}\n"
                                f"Open: {', '.join(n['open']) or 'none / not scanned'}"
                                f"{chr(10) + 'NOT IN TRUSTED BASELINE' if n['rogue'] else ''}")
            else:
                self.setToolTip("")
            super().mouseMoveEvent(event)

        def mousePressEvent(self, event):
            n = self._nearest(event.position())
            if n:
                self.selected = n["ip"]
                self.hostSelected.emit(n["ip"])
                self.update()
            super().mousePressEvent(event)

        def paintEvent(self, event):
            import math
            c = THEMES[self.theme]
            p = QPainter(self)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.fillRect(self.rect(), QColor(c["panel"]))
            cx, cy, radius = self._geom()
            center = QPointF(cx, cy)

            def col(hex_, alpha=255):
                q = QColor(hex_)
                q.setAlpha(int(max(0, min(255, alpha))))
                return q

            # rings = grade boundaries (F inside 60, D, C, B, A outside 90)
            p.setBrush(QBrush(col(c["panel"], 0)))
            for score, label in ((60, "F|D"), (70, "D|C"), (80, "C|B"), (90, "B|A")):
                r = (0.28 + 0.62 * score / 100.0) * radius
                p.setPen(QPen(col(c["border"]), 1))
                p.drawEllipse(center, r, r)
                p.setPen(QPen(col(c["muted"], 160), 1))
                p.setFont(QFont("Segoe UI", 7))
                p.drawText(QPointF(cx + 4, cy - r - 2), label)
            p.setPen(QPen(col(c["border"], 120), 1))
            p.drawLine(QPointF(cx - radius, cy), QPointF(cx + radius, cy))
            p.drawLine(QPointF(cx, cy - radius), QPointF(cx, cy + radius))
            # sweep fan
            p.setPen(Qt.PenStyle.NoPen)
            rect = QRectF(cx - radius, cy - radius, 2 * radius, 2 * radius)
            for i in range(26):
                p.setBrush(QBrush(col(c["accent"], 90 * (1 - i / 26.0))))
                p.drawPie(rect, int(-(self.sweep - i * 2) * 16), 2 * 16)
            if not self.nodes:
                p.setPen(QPen(col(c["muted"]), 1))
                p.setFont(QFont("Segoe UI", 10))
                p.drawText(QRectF(0, cy + 40, self.width(), 24), Qt.AlignmentFlag.AlignCenter,
                           "No hosts yet. Run Network Discovery or a scan, then come back.")
            by_ip = {n["ip"]: n for n in self.nodes}
            # attack path overlay (animated dashes)
            if self.show_paths or self.highlight_path:
                shown = [self.highlight_path] if self.highlight_path else self.paths[:5]
                for path in shown:
                    ips = [i for i in path["hosts"] if i in by_ip]
                    pen = QPen(col(c["danger"], 230 if self.highlight_path else 140), 3 if self.highlight_path else 2)
                    pen.setStyle(Qt.PenStyle.DashLine)
                    pen.setDashOffset(-self.t * 14)
                    p.setPen(pen)
                    for a, b in zip(ips, ips[1:]):
                        p.drawLine(self._pos(by_ip[a]), self._pos(by_ip[b]))
                    if len(ips) == 1:  # single-host path: ring around the host
                        p.setBrush(QBrush(col(c["danger"], 0)))
                        p.drawEllipse(self._pos(by_ip[ips[0]]), 17, 17)
            # hosts
            for n in self.nodes:
                pos = self._pos(n)
                color = c["muted"] if n["grade"] == "?" else grade_color(n["grade"], self.theme)
                diff = (self.sweep - n["angle"]) % 360
                flash = max(0.0, 1 - diff / 40.0) if diff < 40 else 0.0
                pulse = (self.t * 0.8 + n["phase"]) % 1.0
                p.setPen(QPen(col(color, 150 * (1 - pulse)), 1.5))
                p.setBrush(QBrush(col(color, 0)))
                p.drawEllipse(pos, 7 + 12 * pulse, 7 + 12 * pulse)
                p.setPen(QPen(col(c["text"], 90 + 165 * flash), 1.5 if n["ip"] != self.selected else 3))
                p.setBrush(QBrush(col(color, 200 + 55 * flash)))
                p.drawEllipse(pos, 7, 7)
                if n["rogue"]:
                    p.setPen(QPen(col(c["danger"]), 2.5))
                    p.setBrush(QBrush(col(c["danger"], 0)))
                    p.drawEllipse(pos, 13, 13)
                    p.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
                    p.drawText(QPointF(pos.x() + 15, pos.y() - 9), "!")
                if len(self.nodes) <= 30 or n["ip"] == self.selected:
                    p.setPen(QPen(col(c["text"], 210), 1))
                    p.setFont(QFont("Segoe UI", 8))
                    p.drawText(QRectF(pos.x() - 70, pos.y() + 10, 140, 14), Qt.AlignmentFlag.AlignCenter, n["label"][:22])
            # this PC
            glow = 18 + 3 * math.sin(self.t * 2)
            p.setPen(QPen(col(c["accent"]), 2))
            p.setBrush(QBrush(col(c["accent_bg"])))
            p.drawEllipse(center, glow, glow)
            p.setPen(QPen(col(c["text"]), 1))
            p.setFont(QFont("Segoe UI", 7, QFont.Weight.Bold))
            p.drawText(QRectF(cx - 30, cy - 7, 60, 14), Qt.AlignmentFlag.AlignCenter, "THIS PC")
            p.end()

    class RadarPage(QWidget):
        def __init__(self, store):
            super().__init__()
            self.store = store
            lay = QVBoxLayout(self)
            lay.setContentsMargins(26, 22, 26, 22)
            lay.setSpacing(8)
            t = QLabel("Network Radar")
            t.setObjectName("pageTitle")
            lay.addWidget(t)
            d = QLabel("Live map of your inventory. Closer to the centre = lower security grade. Red ring = not in "
                       "your trusted baseline. Dashed red lines = attack paths. Hover or click a host for details.")
            d.setObjectName("muted")
            d.setWordWrap(True)
            lay.addWidget(d)
            row = QHBoxLayout()
            self.toggle = QPushButton("Attack-path overlay: ON")
            self.toggle.setCheckable(True)
            self.toggle.setChecked(True)
            self.toggle.clicked.connect(lambda checked=False: self.on_toggle())
            self.clear_btn = QPushButton("Clear highlight")
            self.clear_btn.clicked.connect(lambda checked=False: self.highlight(None))
            row.addWidget(self.toggle)
            row.addWidget(self.clear_btn)
            row.addStretch()
            lay.addLayout(row)
            self.canvas = RadarCanvas()
            self.canvas.hostSelected.connect(self.on_host)
            lay.addWidget(self.canvas, 1)
            self.details = QLabel("Click a host to see details.")
            self.details.setObjectName("muted")
            self.details.setWordWrap(True)
            lay.addWidget(self.details)
            self.ins = None

        def refresh(self):
            self.ins = compute_insights(self.store)
            self.canvas.set_data(self.ins)

        def set_theme(self, name):
            self.canvas.set_theme(name)

        def on_toggle(self):
            self.canvas.show_paths = self.toggle.isChecked()
            self.toggle.setText("Attack-path overlay: " + ("ON" if self.toggle.isChecked() else "OFF"))

        def highlight(self, path):
            self.canvas.highlight_path = path
            self.details.setText(f"Highlighted path: {path['title']} ({path['severity']}, {path['score']}/100) → "
                                 f"{', '.join(path['hosts'])}" if path else "Click a host to see details.")

        def on_host(self, ip):
            if not self.ins:
                return
            h = self.ins["inventory"].get(ip, {})
            g = next((x for x in self.ins["grade"]["hosts"] if x["ip"] == ip), None)
            paths = [p["title"] for p in self.ins["paths"] if ip in p["hosts"]]
            self.details.setText(
                f"{ip}  {h.get('hostname', '')}  |  grade {g['grade'] if g else '?'}"
                f"{'' if not g or g['score'] is None else ' (' + str(g['score']) + ')'}  |  open: "
                f"{', '.join(h.get('open', [])) or 'none / not scanned'}  |  paths: {'; '.join(paths) or 'none'}"
                f"{'  |  NOT IN TRUSTED BASELINE' if ip in self.ins['alerts']['rogue'] else ''}")

    # ------------------------------------------------------------------ Command palette
    class CommandPalette(QDialog):
        def __init__(self, parent, entries):
            super().__init__(parent)
            self.entries, self.visible = entries, []
            self.setWindowTitle("Command palette")
            self.resize(580, 400)
            lay = QVBoxLayout(self)
            self.input = QLineEdit()
            self.input.setPlaceholderText("Type to search pages, tools, hosts, attack paths, actions…")
            self.input.textChanged.connect(self.update_results)
            self.input.returnPressed.connect(self.run_selected)
            self.list = QListWidget()
            self.list.itemActivated.connect(lambda item: self.run_selected())
            lay.addWidget(self.input)
            lay.addWidget(self.list, 1)
            hint = QLabel("↑ ↓ to move · Enter to run · Esc to close")
            hint.setObjectName("muted")
            lay.addWidget(hint)
            self.update_results()

        def update_results(self, _text=None):
            self.visible = palette_rank(self.input.text(), self.entries)
            self.list.clear()
            for e in self.visible:
                self.list.addItem(e["title"])
            if self.visible:
                self.list.setCurrentRow(0)

        def keyPressEvent(self, event):
            key = event.key()
            row = self.list.currentRow()
            if key == Qt.Key.Key_Down:
                self.list.setCurrentRow(min(row + 1, len(self.visible) - 1))
            elif key == Qt.Key.Key_Up:
                self.list.setCurrentRow(max(row - 1, 0))
            else:
                super().keyPressEvent(event)

        def run_selected(self):
            row = self.list.currentRow()
            if 0 <= row < len(self.visible):
                entry = self.visible[row]
                self.accept()
                QTimer.singleShot(0, entry["run"])

    # ------------------------------------------------------------------ Reports
    class ReportsPage(QWidget):
        BUCKETS = ("assessment_runs", "assessment_results", "devices", "scans",
                   "vulnerabilities", "history", "evidence")

        def __init__(self, store):
            super().__init__()
            self.store = store
            lay = QVBoxLayout(self)
            lay.setContentsMargins(26, 22, 26, 22)
            lay.setSpacing(12)
            t = QLabel("Reports")
            t.setObjectName("pageTitle")
            lay.addWidget(t)
            d = QLabel("Exports include an executive summary, security grades, attack paths and all stored records. "
                       "Every export is sealed into a tamper-evident hash chain; use Verify to prove a report is unchanged.")
            d.setObjectName("muted")
            d.setWordWrap(True)
            lay.addWidget(d)
            row = QHBoxLayout()
            self.fmt = QComboBox()
            self.fmt.addItems(["PDF", "HTML", "CSV", "JSON"])
            b = QPushButton("Export report…")
            b.setObjectName("primary")
            b.clicked.connect(lambda checked=False: self.export())
            v = QPushButton("Verify report…")
            v.clicked.connect(lambda checked=False: self.verify())
            row.addWidget(QLabel("Format:"))
            row.addWidget(self.fmt)
            row.addWidget(b)
            row.addWidget(v)
            row.addStretch()
            lay.addLayout(row)
            self.summary = QLabel()
            self.summary.setObjectName("muted")
            lay.addWidget(self.summary)
            self.chain = QLabel()
            self.chain.setObjectName("muted")
            lay.addWidget(self.chain)
            lay.addWidget(QLabel("Previous exports"))
            self.table = make_table(["Time (UTC)", "Format", "Size (bytes)", "Sealed", "Path"])
            lay.addWidget(self.table)
            self.refresh()

        def refresh(self):
            self.summary.setText("Stored records: " + ", ".join(f"{b}={self.store.count(b)}" for b in self.BUCKETS))
            ch = verify_chain(self.store)
            self.chain.setText(f"Report seal chain: {'intact' if ch['ok'] else 'PROBLEM - ' + '; '.join(ch['problems'])}"
                               f" ({ch['seals']} seal(s))")
            rows = [[r.get("created_at", "")[:19].replace("T", " "), r.get("format", ""),
                     r.get("size_bytes", ""), "Yes" if r.get("sealed") else "No", r.get("path", "")]
                    for r in reversed(self.store.read("report_exports"))]
            fill_table(self.table, rows)
            self.table.resizeColumnsToContents()

        def build_payload(self):
            ins = compute_insights(self.store)
            return {"generated_by": f"{APP_NAME} {APP_VERSION}", "generated_at": utcnow(),
                    "executive_summary": executive_summary(ins),
                    "security_grade_by_host": ins["grade"]["hosts"],
                    "attack_paths": [{"severity": p["severity"], "score": p["score"], "title": p["title"],
                                      "hosts": ", ".join(p["hosts"]), "how_to_break_it": "; ".join(p["mitigation"])}
                                     for p in ins["paths"]],
                    "records": {b: self.store.read(b) for b in self.BUCKETS}}

        def export(self):
            ext = "." + self.fmt.currentText().lower()
            start = Path.home() / "Documents"
            start = start if start.is_dir() else Path.home()
            path, _ = QFileDialog.getSaveFileName(self, "Export NetScope Report",
                                                  str(start / f"NetScope_Report{ext}"),
                                                  f"{self.fmt.currentText()} (*{ext})")
            if not path:
                return
            out = Path(path).with_suffix(ext)
            try:
                payload = self.build_payload()
                records = payload["records"]
                if ext == ".pdf":
                    export_pdf(out, "NetScope Assessment Report", payload)
                elif ext == ".html":
                    export_html(out, "NetScope Assessment Report", payload)
                elif ext == ".csv":
                    rows = [{"record_type": b, **{k: (json.dumps(v, ensure_ascii=False, default=str)
                                                      if isinstance(v, (dict, list)) else v)
                                                  for k, v in rec.items()}}
                            for b, recs in records.items() for rec in recs]
                    export_csv(out, rows)
                else:
                    export_json(out, payload)
                if not out.is_file() or out.stat().st_size == 0:
                    raise RuntimeError("Report file was not created.")
                seal = seal_file(self.store, out)
                self.store.append("report_exports", {"path": str(out.resolve()), "format": ext[1:].upper(),
                                                     "size_bytes": out.stat().st_size, "sealed": True,
                                                     "sha256": seal["sha256"]})
                self.store.append("history", {"action": "Report exported", "target": str(out), "summary": ext[1:].upper() + " (sealed)"})
                self.refresh()
                QMessageBox.information(self, "Export successful",
                                        f"Saved and sealed:\n{out}\n\nSeal file: {out.name}.seal.json (keep it next to the report).")
            except Exception as exc:
                QMessageBox.critical(self, "Export failed", f"{type(exc).__name__}: {exc}")

        def verify(self):
            path, _ = QFileDialog.getOpenFileName(self, "Select a NetScope report to verify")
            if not path:
                return
            try:
                res = verify_seal(self.store, path)
            except Exception as exc:
                QMessageBox.critical(self, "Verify failed", f"{type(exc).__name__}: {exc}")
                return
            lines = [f"{'✔' if c['ok'] else '✖'} {c['check']}: {c['detail']}" for c in res["checks"]]
            box = QMessageBox.information if res["ok"] else QMessageBox.warning
            box(self, "Report verified - authentic" if res["ok"] else "Verification FAILED", "\n".join(lines))

    # ------------------------------------------------------------------ Main window
    def fade_in(widget):
        """Short fade-in used for page transitions."""
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", widget)
        anim.setDuration(240)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.finished.connect(lambda: widget.setGraphicsEffect(None))
        widget._fade = anim
        anim.start()

    class MainWindow(QMainWindow):
        NAV = [("Dashboard", "▣"), ("Toolbox", "⚙"), ("Security Posture", "◉"), ("Attack Paths", "⇉"),
               ("Time Machine", "◷"), ("Network Radar", "◎"), ("Activity History", "☰"), ("Reports", "⎙")]

        def __init__(self):
            super().__init__()
            self.store = JsonStore()
            self.settings = self.store.read_json("settings.json", {}) or {}
            state["theme"] = self.settings.get("theme", "dark") if self.settings.get("theme") in THEMES else "dark"
            self.setWindowTitle("NetScope - Network Security, Intelligence & Assessment")
            self.resize(1480, 920)
            self.setMinimumSize(1100, 700)
            central = QWidget()
            lay = QHBoxLayout(central)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.setSpacing(0)
            self.setCentralWidget(central)
            side = QFrame()
            side.setObjectName("sidebar")
            side.setFixedWidth(248)
            sv = QVBoxLayout(side)
            sv.setContentsMargins(12, 18, 12, 12)
            brand = QLabel("◈  NetScope")
            brand.setObjectName("brand")
            sv.addWidget(brand)
            sub = QLabel("NETWORK SECURITY WORKSTATION")
            sub.setObjectName("muted")
            sv.addWidget(sub)
            sv.addSpacing(10)
            search = QPushButton("⌕  Search…   Ctrl+K")
            search.setObjectName("navButton")
            search.clicked.connect(lambda checked=False: self.open_palette())
            sv.addWidget(search)
            sv.addSpacing(6)
            self.stack = QStackedWidget()
            radar = RadarPage(self.store)
            self.pages = {
                "Dashboard": Dashboard(self.store, self.navigate),
                "Toolbox": Toolbox(self.store),
                "Security Posture": PosturePage(self.store),
                "Attack Paths": PathsPage(self.store, self.show_path_on_radar),
                "Time Machine": TimeMachinePage(self.store, self.refresh_current),
                "Network Radar": radar,
                "Activity History": HistoryPage(self.store),
                "Reports": ReportsPage(self.store)}
            self.buttons = {}
            for name, glyph in self.NAV:
                self.stack.addWidget(self.pages[name])
                b = QPushButton(f"{glyph}   {name}")
                b.setObjectName("navButton")
                b.setCheckable(True)
                b.clicked.connect(lambda checked=False, n=name: self.navigate(n))
                sv.addWidget(b)
                self.buttons[name] = b
            sv.addStretch()
            self.theme_btn = QPushButton()
            self.theme_btn.clicked.connect(lambda checked=False: self.toggle_theme())
            sv.addWidget(self.theme_btn)
            info = detect_platform()
            foot = QLabel(f"{info['system']}  •  v{APP_VERSION}" + ("  •  admin" if info["is_admin"] else ""))
            foot.setObjectName("muted")
            sv.addWidget(foot)
            lay.addWidget(side)
            lay.addWidget(self.stack, 1)
            self.shortcut = QShortcut(QKeySequence("Ctrl+K"), self)
            self.shortcut.activated.connect(self.open_palette)
            self.apply_theme()
            self.navigate("Dashboard")

        # -- theme
        def apply_theme(self):
            self.setStyleSheet(build_stylesheet(state["theme"]))
            self.pages["Network Radar"].set_theme(state["theme"])
            self.theme_btn.setText("◐   Switch to light theme" if state["theme"] == "dark" else "◐   Switch to dark theme")

        def toggle_theme(self):
            state["theme"] = "light" if state["theme"] == "dark" else "dark"
            self.settings["theme"] = state["theme"]
            try:
                self.store.write_json("settings.json", self.settings)
            except OSError:
                pass
            self.apply_theme()
            self.refresh_current()

        # -- navigation
        def navigate(self, name):
            if name not in self.pages:
                return
            page = self.pages[name]
            self.stack.setCurrentWidget(page)
            for n, b in self.buttons.items():
                b.setChecked(n == name)
            if hasattr(page, "refresh"):
                page.refresh()
            fade_in(page)
            self.statusBar().showMessage(f"{name}  |  Authorized assessment only  |  Ctrl+K to search", 6000)

        def refresh_current(self):
            page = self.stack.currentWidget()
            if hasattr(page, "refresh"):
                page.refresh()

        def show_path_on_radar(self, path):
            self.navigate("Network Radar")
            self.pages["Network Radar"].highlight(path)

        # -- command palette
        def palette_entries(self):
            entries = [{"title": f"Go to {n}", "keywords": "open page", "run": lambda n=n: self.navigate(n)}
                       for n, _ in self.NAV]
            tb = self.pages["Toolbox"]
            for name, spec in tb.tools.items():
                entries.append({"title": f"Tool: {name}", "keywords": spec["desc"],
                                "run": lambda n=name: (self.navigate("Toolbox"), tb.select_tool(n))})
            entries += [
                {"title": "Toggle light / dark theme", "keywords": "appearance colors", "run": self.toggle_theme},
                {"title": "Export report…", "keywords": "pdf html csv json seal", "run": lambda: self.navigate("Reports")},
                {"title": "Verify a sealed report…", "keywords": "tamper integrity authentic",
                 "run": lambda: (self.navigate("Reports"), self.pages["Reports"].verify())},
                {"title": "Trust all current devices (set baseline)", "keywords": "rogue device alarm",
                 "run": lambda: (self.navigate("Time Machine"), self.pages["Time Machine"].set_baseline())}]
            try:
                ins = compute_insights(self.store)
                for h in ins["grade"]["hosts"][:40]:
                    entries.append({"title": f"Host: {h['ip']} {h['hostname']} (grade {h['grade']})", "keywords": "radar device",
                                    "run": lambda: self.navigate("Network Radar")})
                for p in ins["paths"]:
                    entries.append({"title": f"Path: {p['title']} [{p['severity']}]", "keywords": "attack " + " ".join(p["hosts"]),
                                    "run": lambda p=p: self.show_path_on_radar(p)})
                for r in list(reversed(self.store.read("history")))[:25]:
                    entries.append({"title": f"History: {r.get('action', '')} {r.get('target', '')}", "keywords": r.get("summary", ""),
                                    "run": lambda: self.navigate("Activity History")})
            except Exception:
                pass  # palette must never fail because of damaged data
            return entries

        def open_palette(self):
            dlg = CommandPalette(self, self.palette_entries())
            dlg.input.setFocus()
            dlg.exec()

        def closeEvent(self, event):
            for page in self.pages.values():
                if isinstance(page, BackgroundMixin):
                    page.stop_worker()
            event.accept()

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    window = MainWindow()
    window.show()
    return app.exec()


# =============================================================================
# CLI: --check / --selftest / --build-c / GUI
# =============================================================================
def check_dependencies() -> int:
    import importlib.util
    print(f"{APP_NAME} {APP_VERSION} dependency check")
    print("Python:", sys.version.split()[0], "|", sys.executable)
    print("Platform:", sys.platform)
    for name in ("PySide6", "dns", "reportlab", "psutil"):
        print(f"Python package {name}: {'OK' if importlib.util.find_spec(name) else 'MISSING'}")
    for name in ("nmap", "rustscan", "tshark", "whois", "gcc"):
        print(f"External tool {name}: {shutil.which(name) or 'NOT FOUND (optional unless you need it)'}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--check" in argv:
        return check_dependencies()
    if "--selftest" in argv:
        import unittest
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SelfTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if "--build-c" in argv:
        print(build_native())
        return 0
    return run_gui()


# =============================================================================
# SELF-TESTS (engine level; no GUI, no internet, no scanning of real hosts)
# =============================================================================
import unittest
from unittest import mock


class SelfTests(unittest.TestCase):
    def test_store_roundtrip_and_malformed_line(self):
        with tempfile.TemporaryDirectory() as d:
            s = JsonStore(d)
            rec = s.append("devices", {"ip": "127.0.0.1"})
            self.assertIn("id", rec)
            self.assertIn("created_at", rec)
            with (Path(d) / "devices" / "records.jsonl").open("a", encoding="utf-8") as f:
                f.write("{broken\n")
            s.append("devices", {"ip": "10.0.0.1"})
            self.assertEqual([r["ip"] for r in s.read("devices")], ["127.0.0.1", "10.0.0.1"])
            with self.assertRaises(ValueError):
                s.append("../evil", {})

    def test_validation(self):
        for good in ("127.0.0.1", "192.168.1.0/24", "example.com", "a-b.example.org", "::1"):
            self.assertEqual(validate_target(good), good)
        for bad in ("127.0.0.1;whoami", "", "-oX /tmp/x", "a b", "x|y", "$(id)", "a&b"):
            with self.assertRaises(ValueError, msg=bad):
                validate_target(bad)
        with self.assertRaises(ValueError):
            validate_host("10.0.0.0/24")

    def test_nmap_xml_parse(self):
        xml = ('<nmaprun><host><status state="up"/><address addr="aa:bb" addrtype="mac"/>'
               '<address addr="127.0.0.1" addrtype="ipv4"/><hostnames><hostname name="localhost"/></hostnames>'
               '<ports><port protocol="tcp" portid="80"><state state="open"/>'
               '<service name="http" product="nginx" version="1.2"/></port></ports></host></nmaprun>')
        h = parse_nmap_xml(xml)[0]
        self.assertEqual(h["ip"], "127.0.0.1")
        self.assertEqual(h["hostname"], "localhost")
        self.assertEqual(h["ports"][0]["port"], 80)
        self.assertEqual(h["ports"][0]["product"], "nginx")

    def test_nmap_command_construction(self):
        with mock.patch("shutil.which", return_value="/usr/bin/nmap"):
            cmd = build_nmap_command("127.0.0.1", "Quick Scan")
            self.assertEqual(cmd[-2:], ["--", "127.0.0.1"])
            with self.assertRaises(ValueError):
                build_nmap_command("127.0.0.1;whoami")
            with self.assertRaises(ValueError):
                build_nmap_command("127.0.0.1", extra_ports="80; rm")
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(RuntimeError):
                build_nmap_command("127.0.0.1")

    def test_rustscan_xml_extraction(self):
        xml = '<?xml version="1.0"?><nmaprun><host></host></nmaprun>'
        self.assertEqual(_extract_nmap_xml("banner\n" + xml + "\nDone"), xml)
        with self.assertRaises(RuntimeError):
            _extract_nmap_xml("no xml here")

    def test_rustscan_no_open_ports_is_not_an_error(self):
        with mock.patch("shutil.which", side_effect=lambda n: f"/usr/bin/{n}"), \
             mock.patch(f"{__name__}._run_process", return_value=(0, "Nmap done: 0 hosts", "")):
            res = scan_fast("127.0.0.1")
        self.assertEqual(res["hosts"], [])
        self.assertEqual(res["open_port_count"], 0)

    def test_run_process_large_output_no_deadlock(self):
        code, out, _ = _run_process([sys.executable, "-c", "print('x'*2000000)"], 30)
        self.assertEqual(code, 0)
        self.assertGreater(len(out), 1000000)

    def test_run_process_timeout_and_cancel(self):
        with self.assertRaises(TimeoutError):
            _run_process([sys.executable, "-c", "import time; time.sleep(30)"], 1)
        ev = threading.Event()
        threading.Timer(0.5, ev.set).start()
        with self.assertRaises(RuntimeError):
            _run_process([sys.executable, "-c", "import time; time.sleep(30)"], 30, ev)

    def test_exposure_findings(self):
        r = assess_host({"ports": [{"port": 23, "state": "open", "service": "telnet"},
                                   {"port": 3389, "state": "closed"}]})
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["severity"], "High")
        self.assertIn("TCP/23", r[0]["evidence"])
        self.assertIsNone(r[0]["cve"])

    def test_topology_no_fake_links_and_dedupe(self):
        g = build_topology([{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}, {"ip": "10.0.0.2"}])
        self.assertEqual(len(g["nodes"]), 2)
        self.assertEqual(g["edges"], [])

    def test_discover_limits_and_localhost(self):
        with self.assertRaises(ValueError):
            discover("10.0.0.0/8")
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]
        try:
            real_probe = _probe_host
            with mock.patch(f"{__name__}._probe_host", side_effect=lambda a, p, t: real_probe(a, (port,), t)):
                res = discover("127.0.0.1/32")
            self.assertEqual(res[0]["ip"], "127.0.0.1")
        finally:
            srv.close()

    def test_dns_fallback(self):
        rows = dns_lookup("localhost", "A")
        self.assertTrue(rows and rows[0]["type"] == "A")
        with self.assertRaises(ValueError):
            dns_lookup("bad domain;x")

    def test_hashes_and_files(self):
        self.assertEqual(hash_text("abc")["md5"], "900150983cd24fb0d6963f7d28e17f72")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.bin"
            p.write_bytes(b"abc")
            self.assertEqual(hash_file(p)["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d")
            ok = check_integrity(p, "900150983cd24fb0d6963f7d28e17f72")
            self.assertTrue(ok["match"])
            self.assertFalse(check_integrity(p, "0" * 32)["match"])
            self.assertEqual(file_info(p)["size_bytes"], 3)
            log = Path(d) / "x.log"
            log.write_text("ok\nERROR boom\nlogin failed\nfine\n", encoding="utf-8")
            res = analyze_log(log)
            self.assertEqual(res["lines"], 4)
            self.assertEqual(len(res["matches"]), 2)
        self.assertIn("MD5 / NTLM", identify_hash("0" * 32)["possible_algorithms"])
        self.assertEqual(password_strength("Abcdef123456!")["score"], "5/5")

    def test_category_assessment_flows(self):
        with mock.patch(f"{__name__}.rustscan_available", return_value=False), \
             mock.patch(f"{__name__}.nmap_scan", return_value=[{"ip": "192.0.2.10", "status": "up", "ports": []}]) as m:
            rep = run_category_assessment("NETWORK INTELLIGENCE", "192.0.2.10")
            self.assertEqual(rep["results"][0]["tool"], "Nmap service scan")
            m.assert_called_once()
        rep = run_category_assessment("DIGITAL FORENSICS", "")
        self.assertEqual(rep["results"], [])
        self.assertTrue(rep["skipped"])
        rep = run_category_assessment("SYSTEM", "")
        self.assertEqual(rep["results"][0]["tool"], "Platform")
        with self.assertRaises(ValueError):
            run_category_assessment("NETWORK INTELLIGENCE", "")
        with self.assertRaises(ValueError):
            run_category_assessment("BOGUS", "x")
        hosts = [{"ip": "192.0.2.1", "status": "up", "ports": [{"port": 445, "state": "open", "service": "smb"}]}]
        with mock.patch(f"{__name__}.nmap_scan", return_value=hosts):
            rep = run_category_assessment("VULNERABILITY MANAGEMENT", "192.0.2.1")
        self.assertEqual(rep["results"][1]["result"][0]["title"], "SMB exposed")

    def test_web_url_rules(self):
        with self.assertRaises(ValueError):
            http_headers("http://example.com")
        self.assertEqual(_normalize_https_url("example.com/x"), "https://example.com/x")

    def test_extract_hosts_helper(self):
        self.assertEqual(_extract_hosts({"hosts": [{"ip": "1"}]}), [{"ip": "1"}])
        self.assertEqual(_extract_hosts([{"ip": "1", "ports": []}]), [{"ip": "1", "ports": []}])
        self.assertEqual(_extract_hosts([{"ip": "1"}]), [])

    def test_exporters(self):
        payload = {"records": {"devices": [{"ip": "1.1.1.1", "x": "<b>"}], "history": []},
                   "generated_by": "t"}
        with tempfile.TemporaryDirectory() as d:
            export_json(Path(d) / "r.json", payload)
            export_html(Path(d) / "r.html", "T", payload)
            export_csv(Path(d) / "r.csv", [{"a": 1}, {"b": 2}])
            export_csv(Path(d) / "e.csv", [])
            self.assertIn("&lt;b&gt;", (Path(d) / "r.html").read_text(encoding="utf-8"))
            try:
                import reportlab  # noqa: F401
            except ImportError:
                self.skipTest("reportlab not installed")
            export_pdf(Path(d) / "r.pdf", "T", payload)
            self.assertTrue((Path(d) / "r.pdf").read_bytes().startswith(b"%PDF"))

    # ---- new feature tests -------------------------------------------------
    @staticmethod
    def _h(ip, ports, known=True, name=""):
        svc = {f"{p}/tcp": "x" for p in ports}
        return {"ip": ip, "hostname": name, "ports_known": known, "open": sorted(svc, key=_port_key_int), "services": svc}

    def test_snapshot_normalization_and_scan_profile(self):
        hosts = [{"ip": "10.0.0.1", "status": "up", "scan_profile": "Quick Scan", "ports": []},
                 {"ip": "10.0.0.2", "status": "down", "ports": []},
                 {"ip": "10.0.0.3", "status": "up", "ports": [
                     {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "nginx", "version": "1"},
                     {"port": 81, "protocol": "tcp", "state": "closed"}]}]
        snap = make_snapshot("t", "10.0.0.0/24", hosts)
        self.assertEqual([h["ip"] for h in snap["hosts"]], ["10.0.0.1", "10.0.0.3"])
        self.assertFalse(snap["hosts"][0]["ports_known"])
        self.assertEqual(snap["hosts"][1]["open"], ["80/tcp"])

    def test_time_machine_diff_and_gone_hosts(self):
        s1 = make_snapshot("a", "10.0.0.0/24", [
            {"ip": "10.0.0.1", "status": "up", "ports": [{"port": 22, "protocol": "tcp", "state": "open"}]},
            {"ip": "10.0.0.2", "status": "up", "ports": []}])
        s2 = make_snapshot("b", "10.0.0.0/24", [
            {"ip": "10.0.0.1", "status": "up", "ports": [{"port": 3389, "protocol": "tcp", "state": "open"}]},
            {"ip": "10.0.0.9", "status": "up", "ports": []}])
        i0, i1 = inventory_upto([s1, s2], 0), inventory_upto([s1, s2], 1)
        d = diff_inventories(i0, i1)
        self.assertEqual(d["new_hosts"], ["10.0.0.9"])
        self.assertEqual(d["gone_hosts"], ["10.0.0.2"])
        self.assertEqual(d["opened_ports"], {"10.0.0.1": ["3389/tcp"]})
        self.assertEqual(d["closed_ports"], {"10.0.0.1": ["22/tcp"]})
        # discovery (ports unknown) must not erase known ports
        disc = make_snapshot("d", "10.0.0.0/24", [{"ip": "10.0.0.1", "status": "online", "ports": []}], ports_known=False)
        inv = inventory_upto([s1, disc], 1)
        self.assertEqual(inv["10.0.0.1"]["open"], ["22/tcp"])
        # incomplete scans (RustScan) must not mark absent hosts as gone
        partial = make_snapshot("r", "10.0.0.0/24", [], complete=False)
        self.assertIn("10.0.0.2", inventory_upto([s1, partial], 1))

    def test_partial_verify_scan_keeps_other_ports(self):
        full = make_snapshot("f", "10.0.0.5", [{"ip": "10.0.0.5", "status": "up", "scan_profile": "Standard Scan", "ports": [
            {"port": 3389, "protocol": "tcp", "state": "open", "service": "rdp"},
            {"port": 445, "protocol": "tcp", "state": "open", "service": "smb"}]}])
        fixed = make_snapshot("verify", "10.0.0.5", [{"ip": "10.0.0.5", "status": "up", "scan_profile": "Custom ports", "ports": [
            {"port": 3389, "protocol": "tcp", "state": "closed"}]}])
        inv = inventory_upto([full, fixed], 1)
        self.assertEqual(inv["10.0.0.5"]["open"], ["445/tcp"])
        self.assertEqual(diff_inventories(inventory_upto([full, fixed], 0), inv)["closed_ports"], {"10.0.0.5": ["3389/tcp"]})
        with mock.patch("shutil.which", return_value="/usr/bin/nmap"):
            self.assertIn("-Pn", build_nmap_command("10.0.0.5", extra_ports="3389"))

    def test_baseline_and_rogue(self):
        with tempfile.TemporaryDirectory() as d:
            st = JsonStore(d)
            inv = {"10.0.0.1": self._h("10.0.0.1", []), "10.0.0.2": self._h("10.0.0.2", [])}
            self.assertFalse(baseline_alerts(inv, load_baseline(st))["has_baseline"])
            save_baseline(st, inv)
            inv2 = {"10.0.0.1": inv["10.0.0.1"], "10.0.0.66": self._h("10.0.0.66", [])}
            a = baseline_alerts(inv2, load_baseline(st))
            self.assertEqual(a["rogue"], ["10.0.0.66"])
            self.assertEqual(a["missing"], ["10.0.0.2"])

    def test_security_grade(self):
        inv = {"10.0.0.1": self._h("10.0.0.1", [443]), "10.0.0.2": self._h("10.0.0.2", [23, 445, 3389, 6379]),
               "10.0.0.3": self._h("10.0.0.3", [], known=False)}
        g = security_grade(inv)
        by = {h["ip"]: h for h in g["hosts"]}
        self.assertEqual(by["10.0.0.1"]["grade"], "A")
        self.assertEqual(by["10.0.0.2"]["grade"], "F")
        self.assertEqual(by["10.0.0.3"]["grade"], "?")
        self.assertEqual(g["hosts"][0]["ip"], "10.0.0.2")  # worst first
        self.assertIn(g["overall_grade"], "CDF")
        self.assertEqual(security_grade({})["overall_grade"], "–")

    def test_attack_paths(self):
        inv = {"10.0.0.5": self._h("10.0.0.5", [3389, 445], name="winsrv"),
               "10.0.0.6": self._h("10.0.0.6", [80, 6379], name="web"),
               "10.0.0.7": self._h("10.0.0.7", [23]),
               "10.0.0.8": self._h("10.0.0.8", [], known=False)}
        paths = compute_attack_paths(inv)
        titles = [p["title"] for p in paths]
        self.assertIn("Remote login to file-share lateral movement on winsrv", titles)
        self.assertIn("Web foothold to data-store access on web", titles)
        self.assertIn("Cleartext credential capture on 10.0.0.7", titles)
        self.assertEqual(len(titles), len(set(titles)))
        self.assertTrue(any(t.startswith("Pivot from") for t in titles))
        self.assertEqual(paths, sorted(paths, key=lambda p: (-p["score"], p["title"])))
        self.assertTrue(all(0 <= p["score"] <= 100 and p["narrative"] and p["mitigation"] for p in paths))
        self.assertEqual(compute_attack_paths({}), [])
        self.assertEqual(compute_attack_paths({"1.1.1.1": self._h("1.1.1.1", [445, 3389], known=False)}), [])

    def test_playbooks(self):
        pb = playbook_for_port(3389, "10.0.0.5")
        self.assertIn("nmap -Pn -p 3389 10.0.0.5", format_playbook(pb))
        self.assertTrue(pb["windows"] and pb["linux"])
        self.assertIn("5555", playbook_for_port(5555)["linux"][0])
        for bad in (0, 70000):
            with self.assertRaises(ValueError):
                playbook_for_port(bad)
        for port in _PLAYBOOKS:
            self.assertTrue(playbook_for_port(port)["linux"], port)

    def test_insights_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            st = JsonStore(d)
            self.assertEqual(compute_insights(st)["grade"]["overall_grade"], "–")
            hosts = [{"ip": "10.0.0.5", "status": "up", "scan_profile": "Standard Scan", "ports": [
                {"port": 3389, "protocol": "tcp", "state": "open", "service": "ms-wbt-server"},
                {"port": 445, "protocol": "tcp", "state": "open", "service": "smb"}]}]
            st.append("snapshots", make_snapshot("scan", "10.0.0.5", hosts))
            ins = compute_insights(st)
            self.assertEqual(len(ins["inventory"]), 1)
            self.assertEqual(len(ins["trend"]), 1)
            self.assertGreaterEqual(ins["findings"], 2)
            summary = executive_summary(ins)
            self.assertEqual(summary["hosts_in_inventory"], 1)
            json.dumps(summary)

    def test_tamper_evident_seals(self):
        with tempfile.TemporaryDirectory() as d:
            st = JsonStore(Path(d) / "data")
            f1, f2 = Path(d) / "a.json", Path(d) / "b.html"
            f1.write_text("report one", encoding="utf-8")
            f2.write_text("report two", encoding="utf-8")
            seal_file(st, f1)
            seal_file(st, f2)
            self.assertTrue(verify_seal(st, f1)["ok"])
            self.assertTrue(verify_chain(st)["ok"])
            f1.write_text("report ONE edited", encoding="utf-8")
            res = verify_seal(st, f1)
            self.assertFalse(res["ok"])
            self.assertFalse([c for c in res["checks"] if c["check"] == "Report content unchanged"][0]["ok"])
            f1.write_text("report one", encoding="utf-8")
            self.assertTrue(verify_seal(st, f1)["ok"])
            # remove the first chain record -> chain must break
            path = st.base / "report_chain" / "records.jsonl"
            lines = path.read_text(encoding="utf-8").splitlines()
            path.write_text(lines[1] + "\n", encoding="utf-8")
            self.assertFalse(verify_chain(st)["ok"])
            # editing a record (forged hash) is detected
            rec = json.loads(lines[0]); rec["sha256"] = "0" * 64
            path.write_text(json.dumps(rec) + "\n" + lines[1] + "\n", encoding="utf-8")
            self.assertFalse(verify_chain(st)["ok"])
            f2.with_name("b.html.seal.json").unlink()
            self.assertFalse(verify_seal(st, f2)["ok"])

    def test_palette_ranking(self):
        entries = [{"title": "Go to Dashboard"}, {"title": "Tool: DNS Lookup", "keywords": "domain records"},
                   {"title": "Toggle light/dark theme"}, {"title": "Tool: Hash Generator"}]
        self.assertEqual(palette_rank("dns", entries)[0]["title"], "Tool: DNS Lookup")
        self.assertEqual(palette_rank("domain", entries)[0]["title"], "Tool: DNS Lookup")
        self.assertEqual(palette_rank("tgl", entries)[0]["title"], "Toggle light/dark theme")  # subsequence
        self.assertEqual(palette_rank("zzzz", entries), [])
        self.assertEqual(len(palette_rank("", entries)), 4)

    def test_radar_geometry_and_themes(self):
        a1, r1 = radar_polar("10.0.0.1", 100)
        self.assertEqual((a1, r1), radar_polar("10.0.0.1", 100))
        self.assertTrue(0 <= a1 < 360)
        self.assertLess(radar_polar("10.0.0.1", 10)[1], r1)  # worse grade nearer the centre
        self.assertEqual(radar_polar("x", None)[1], 0.5)
        for name in THEMES:
            qss = build_stylesheet(name)
            self.assertNotIn("$", qss)
            self.assertIn(THEMES[name]["accent"], qss)
        self.assertEqual(set(THEMES["dark"]), set(THEMES["light"]))
        self.assertEqual(grade_color("F"), THEMES["dark"]["danger"])

    def test_native_helper(self):
        if not shutil.which("gcc"):
            self.skipTest("gcc not installed (optional)")
        build_native()
        lib = load_native()
        self.assertEqual(lib.ns_add(2, 3), 5)
        self.assertTrue(lib.ns_version().startswith(b"NetScope"))


if __name__ == "__main__":
    raise SystemExit(main())

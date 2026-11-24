# NetScope 1.2
Network security assessment workstation (PySide6 desktop app, Windows 10/11 and Linux/Kali).
The whole application is one file: **`netscope.py`**.

**Authorized use only** — scan systems you own or have written permission to test.

## Run (Windows)
1. Install 64-bit Python 3.10+ (tick *Add python.exe to PATH*).
2. Extract the ZIP to a normal folder (e.g. `C:\NetScope`).
3. Double-click `run_netscope_windows.bat` (first run creates `.venv` and installs packages).
4. Optional but recommended: install **Nmap** (https://nmap.org/download.html, with Npcap) and restart the launcher.

Linux/Kali: `./run_netscope_kali.sh` (install `nmap`, optionally `rustscan`, `tshark`, `whois` with apt).

## Commands
    python netscope.py              # start the GUI
    python netscope.py --check      # show missing packages / tools
    python netscope.py --selftest   # 29 engine tests (no GUI, no network, no scanning)
    python netscope.py --build-c    # optional native C helper (needs gcc)

## Pages
- **Dashboard** – grade, rogue alarm, metrics; pick a category + target; runs the supported checks, shows results, can be cancelled.
- **Toolbox** – individual tools: network discovery, interfaces, Nmap / RustScan scans, DNS, WHOIS,
  traceroute, HTTP headers, TLS certificate, hashing, file integrity, file analysis, log analyzer,
  PCAP summary (TShark), password strength, evidence manager, connection/bandwidth monitor, tool inventory.
- **Security Posture**, **Attack Paths**, **Time Machine**, **Network Radar**, **Activity History**, **Reports** (PDF/HTML/CSV/JSON, sealed).

Data is stored as JSONL under `data/<bucket>/records.jsonl` next to `netscope.py`.

## Honest limitations
- Exposure findings are port-based heuristics, **not** CVE verification.
- Wireless, forensics suites, OSINT feeds, ZAP/Gobuster etc. are not integrated; they are reported as *skipped*, never faked.
- Nmap/RustScan/TShark/whois must be installed separately. Some scan types need Administrator rights.

## What's new in 1.2
- **Security grade (A-F)** per host and for the whole network, with a trend over time.
- **Attack paths** - plain-language stories that chain exposed services (hypothetical; nothing is exploited).
- **Fix-it playbooks** - copy-paste Windows/Linux commands per finding, plus **Re-scan to verify**. NetScope never runs the commands for you.
- **Time Machine** - replay saved scans with a slider / Play button; see hosts appear or vanish and ports open or close.
- **Trusted baseline + rogue-device alarm** - banner on the Dashboard and red rings on the radar.
- **Network Radar** - animated live map. Closer to the centre = lower grade; attack-path overlay; hover or click a host.
- **Command palette (Ctrl+K)** - jump to any page, tool, host, attack path or action.
- **Tamper-evident reports** - every export is sealed in a hash chain (+ local HMAC key). Use *Verify report...* to prove a
  report is unchanged. Keep `<report>.seal.json` next to the report. PDF/HTML/JSON include an executive summary.
- **Light/dark theme** (remembered), page fade transitions, animated counters.

Notes: seals prove integrity on the machine that created them (key in `data/report.key`). Grades and attack paths are
exposure heuristics from scanned ports, not CVE verification. Run a scan (or Network Discovery) first so the new pages have data.

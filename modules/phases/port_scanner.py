"""
modules/phases/port_scanner.py

Phase 3: Port scanning via naabu.

Scans the public IPs discovered during DNS resolution (the scanner now
filters private/loopback IPs out before this phase — finding #14).

What this version fixes vs the previous one
───────────────────────────────────────────
· web_ports_from_scan no longer silently drops web ports (finding #15)
    The old version kept only ports in a fixed _WEB_PORT_HINTS whitelist,
    so a real service on 8983 (Solr), 10000 (Webmin), etc. was dropped and
    never probed. It now keeps every open port EXCEPT a small set of
    clearly-non-web ports (SSH, MySQL, …), so unusual web ports survive
    while httpx isn't pointed at SSH/DB ports. The default web ports are
    still always included as a safety net for CDN-fronted hosts whose real
    IPs naabu skipped via --exclude-cdn.

    (The stronger fix — per-host port targeting instead of one flattened
    list — lives in http_probe.py, which consumes ports.json + resolved.txt
    directly. web_ports_from_scan remains the fallback used when that
    per-host data isn't available.)

Output files:
  open_ports.txt   — "IP:PORT" pairs, one per line
  ports.json       — {IP: [port, port, ...]} sorted per IP
"""

import json
import tempfile
from pathlib import Path

from modules.utils.process import run_cmd
from modules.utils.output  import append_to_raw, write_clean, safe_print

# Ports we never want httpx to waste a probe on — plainly non-HTTP.
# Anything NOT in here is treated as a possible web port (so 8983, 10000,
# 8888, custom app ports, etc. are kept).
_NON_WEB = {
    21, 22, 23, 25, 53, 110, 111, 135, 137, 138, 139, 143, 161, 162,
    389, 445, 465, 512, 513, 514, 587, 636, 993, 995, 1433, 1521,
    2049, 3306, 3389, 5432, 5900, 6379, 11211, 27017, 27018, 5984,
}

# Ports worth flagging in the summary even if not web.
_INTERESTING = {
    21: "FTP",   22: "SSH",   23: "Telnet", 25: "SMTP",
    53: "DNS",   110: "POP3", 143: "IMAP",  389: "LDAP",
    445: "SMB",  3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 27017: "MongoDB",
}


def run_port_scan(domain: str, ips_file: Path,
                  out_dir: Path, cfg: dict, available: dict) -> set:
    """
    Run naabu against all IPs in ips_file (public IPs only).
    Returns set of open "IP:PORT" pairs (used by the HTTP probe phase).
    """
    raw_file       = out_dir / "subdomains_raw.txt"
    ports_out      = out_dir / "open_ports.txt"
    ports_json_out = out_dir / "ports.json"

    if not available.get("naabu"):
        safe_print("    [!] naabu not installed — port scanning skipped")
        safe_print("        Install: sudo recon_raptor install")
        append_to_raw(raw_file, "naabu", "naabu not installed\n")
        return set()

    with open(ips_file, 'r', errors='replace') as fh:
        ips = [l.strip() for l in fh if l.strip()]

    if not ips:
        safe_print("    [i] No IPs to scan")
        return set()

    threads    = cfg.get('threads', 50)
    port_cfg   = cfg.get('port_scan', {})
    top_ports  = port_cfg.get('top_ports',  1000)
    custom_pts = port_cfg.get('ports',      [])
    rate       = port_cfg.get('rate',       1000)

    tmp = tempfile.NamedTemporaryFile(
        mode='w', suffix='.txt', delete=False, prefix='rr_ips_')
    try:
        tmp.write('\n'.join(ips))
        tmp.close()

        cmd = [
            "naabu",
            "-l",     tmp.name,
            "-silent",
            "-c",     str(threads),
            "-rate",  str(rate),
            "-json",
            "-exclude-cdn",
        ]
        if custom_pts:
            cmd += ["-p", ','.join(str(p) for p in custom_pts)]
            safe_print(f"    [>] naabu  {len(ips)} IPs  ports: {custom_pts} ...",
                       end='', flush=True)
        else:
            cmd += ["-top-ports", str(top_ports)]
            safe_print(f"    [>] naabu  {len(ips)} IPs  top {top_ports} ports ...",
                       end='', flush=True)

        stdout, stderr, _ = run_cmd(cmd, timeout=1800)
        append_to_raw(raw_file, "naabu", stdout + stderr)
    finally:
        Path(tmp.name).unlink(missing_ok=True)

    # ── Parse JSON output ─────────────────────────────────────────────────────
    port_pairs = set()
    ip_ports   = {}

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            ip    = entry.get("ip",   "") or entry.get("host", "")
            port  = entry.get("port", "")
            if ip and port:
                port_pairs.add(f"{ip}:{port}")
                ip_ports.setdefault(ip, []).append(int(port))
        except (json.JSONDecodeError, ValueError):
            if ':' in line and not line.startswith('['):
                port_pairs.add(line)

    for ip in ip_ports:
        ip_ports[ip] = sorted(set(ip_ports[ip]))

    write_clean(ports_out,    port_pairs)
    ports_json_out.write_text(json.dumps(ip_ports, indent=2))

    safe_print(f" {len(port_pairs)} open ports across {len(ip_ports)} IPs")
    safe_print(f"    [+] open_ports.txt: {len(port_pairs)} entries")

    flagged = []
    for ip, ports in sorted(ip_ports.items()):
        hits = {p: _INTERESTING[p] for p in ports if p in _INTERESTING}
        if hits:
            services = "  ".join(f"{p}/{svc}" for p, svc in sorted(hits.items()))
            flagged.append(f"        {ip:<18} {services}")
    if flagged:
        safe_print(f"    [!] Interesting services ({len(flagged)} IPs):")
        for line in flagged:
            safe_print(line)

    return port_pairs


def web_ports_from_scan(port_pairs: set) -> list:
    """
    Extract ports worth probing with httpx from port-scan results.

    Additive, never purely replacing: the default web ports are always
    included as a safety net (CDN-fronted IPs get skipped by naabu's
    --exclude-cdn while still serving the real site on 80/443). On top of
    that, EVERY open port that isn't a known-non-web port is kept — so
    unusual web ports (8983, 10000, 8888, custom app ports) are probed
    instead of dropped by a narrow whitelist.
    """
    open_ports = set()
    for pair in port_pairs:
        try:
            open_ports.add(int(str(pair).split(':')[-1]))
        except ValueError:
            pass

    always_probe = {80, 443, 8080, 8443}
    web_candidates = {p for p in open_ports if p not in _NON_WEB}
    return sorted(always_probe | web_candidates)
"""
modules/phases/resolver.py

Phase 2: DNS resolution.

For every subdomain in subdomains.txt, queries for:
  A · AAAA · CNAME · MX · NS · TXT

Output files:
  resolved.txt      — "subdomain IP" pairs (A + AAAA records)
  ips.txt           — unique IP addresses only
  cnames.txt        — "subdomain -> cname_target" pairs
  dns_records.txt   — full record dump, one per line

Also attempts a zone transfer (AXFR) against each domain's nameservers
if enabled in config extras.zone_transfer.
"""

import subprocess
import json
from pathlib import Path

from modules.utils.output import append_to_raw, write_clean


def _run(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"[timeout after {timeout}s]", -1
    except FileNotFoundError:
        return "", f"[{cmd[0]} not found]", -1
    except Exception as e:
        return "", str(e), -1


# ── Zone transfer ─────────────────────────────────────────────────────────────

def run_zone_transfer(domain: str, out_dir: Path):
    """
    Attempt AXFR zone transfer against each nameserver for *domain*.
    Results appended to subdomains_raw.txt; any discovered names are
    appended directly to subdomains.txt.
    """
    raw_file = out_dir / "subdomains_raw.txt"

    # Find nameservers
    ns_stdout, _, _ = _run(["dig", "+short", "NS", domain], timeout=10)
    nameservers = [ns.rstrip('.') for ns in ns_stdout.splitlines() if ns.strip()]

    if not nameservers:
        append_to_raw(raw_file, "zone_transfer", "No NS records found\n")
        return

    found_any = False
    subs_file = out_dir / "subdomains.txt"

    for ns in nameservers:
        stdout, stderr, rc = _run(
            ["dig", f"@{ns}", domain, "AXFR", "+noall", "+answer"],
            timeout=15
        )
        append_to_raw(raw_file, f"zone_transfer_{ns}", stdout + stderr)

        if rc == 0 and stdout.strip() and "Transfer failed" not in stdout:
            names = set()
            for line in stdout.splitlines():
                parts = line.split()
                if len(parts) >= 1:
                    name = parts[0].rstrip('.').lower()
                    if name.endswith(f'.{domain}') or name == domain:
                        names.add(name)

            if names:
                print(f"    [!] Zone transfer SUCCESS on {ns} — {len(names)} names")
                # Append new names to subdomains.txt
                existing = set()
                if subs_file.exists():
                    existing = set(subs_file.read_text().splitlines())
                combined = existing | names
                write_clean(subs_file, combined)
                found_any = True

    if not found_any:
        print(f"    [i] Zone transfer: refused by all nameservers (expected)")


# ── Main resolution ───────────────────────────────────────────────────────────

def run_dns_resolution(domain: str, subs_file: Path,
                       out_dir: Path, cfg: dict, available: dict):
    """
    Resolve all subdomains with dnsx and extract every record type.
    """
    raw_file = out_dir / "subdomains_raw.txt"

    if not available.get("dnsx"):
        msg = "dnsx not installed — DNS resolution skipped\n"
        print(f"    [!] {msg.strip()}")
        append_to_raw(raw_file, "dnsx_resolve", msg)
        return

    threads   = cfg.get('threads', 50)
    resolvers = cfg.get('resolvers', './resolvers.txt')

    resolver_args = ["-r", resolvers] if Path(resolvers).exists() else []

    sub_count = sum(1 for _ in open(subs_file))
    print(f"    [>] dnsx resolving {sub_count:,} subdomains ...", end='', flush=True)

    stdout, stderr, _rc = _run([
        "dnsx",
        "-l",    str(subs_file),
        "-silent",
        "-t",    str(threads),
        "-a",            # A records
        "-aaaa",         # AAAA records
        "-cname",        # CNAME records
        "-mx",           # MX records
        "-ns",           # NS records
        "-txt",          # TXT records
        "-resp",         # include resolved values
        "-json",         # structured output
    ] + resolver_args, timeout=600)

    append_to_raw(raw_file, "dnsx_resolve", stdout + stderr)

    # ── Parse JSON (one object per line) ─────────────────────────────────────
    resolved_pairs = []   # "sub IP"
    all_ips        = set()
    cname_pairs    = []   # "sub -> target"
    dns_lines      = []   # full record dump

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        host = rec.get("host", "").lower().rstrip(".")

        for ip in rec.get("a", []):
            all_ips.add(ip)
            resolved_pairs.append(f"{host} {ip}")
            dns_lines.append(f"{host} A {ip}")

        for ip in rec.get("aaaa", []):
            all_ips.add(ip)
            resolved_pairs.append(f"{host} {ip}")
            dns_lines.append(f"{host} AAAA {ip}")

        for cname in rec.get("cname", []):
            target = cname.lower().rstrip(".")
            cname_pairs.append(f"{host} -> {target}")
            dns_lines.append(f"{host} CNAME {target}")

        for mx in rec.get("mx", []):
            dns_lines.append(f"{host} MX {mx.rstrip('.')}")

        for ns in rec.get("ns", []):
            dns_lines.append(f"{host} NS {ns.rstrip('.')}")

        for txt in rec.get("txt", []):
            dns_lines.append(f'{host} TXT "{txt}"')

    # ── Write output files ────────────────────────────────────────────────────
    write_clean(out_dir / "resolved.txt",    resolved_pairs)
    write_clean(out_dir / "ips.txt",         all_ips)
    write_clean(out_dir / "dns_records.txt", dns_lines)

    if cname_pairs:
        write_clean(out_dir / "cnames.txt", cname_pairs)

    print(f" {len(all_ips)} unique IPs")
    print(f"    [+] resolved.txt:    {len(resolved_pairs)} entries")
    if cname_pairs:
        print(f"    [+] cnames.txt:      {len(cname_pairs)} CNAME records")
    print(f"    [+] dns_records.txt: {len(dns_lines)} total records")

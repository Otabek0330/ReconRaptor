"""
modules/phases/resolver.py

Phase 2: DNS resolution.

What this version fixes vs the previous one
───────────────────────────────────────────
· Zone-transfer handoff (works with scanner.py #5 ordering + subdomain.py)
    run_zone_transfer now writes discovered names to _zone.txt instead of
    straight into subdomains.txt. The scanner runs it in Phase 1 before
    merge_subdomains, which folds _zone.txt in — so AXFR names actually
    survive the merge and get resolved/probed. Writing into subdomains.txt
    directly (as before) was pointless: the merge overwrote it.

· DMARC / DKIM records are now actually collected (finding #6, data half)
    The main resolution only queried the target hosts, so `_dmarc.<domain>`
    and DKIM selector records were never fetched — which made
    analyse_email_security() report DMARC/DKIM "MISSING" for every domain,
    always. This phase now explicitly resolves `_dmarc.<host>` for each
    target and common DKIM selectors for the apex, appending the TXT
    records to dns_records.txt in the format extras.py already parses.

    NOTE: the EVALUATION bugs in extras.py (global SPF check instead of
    per-host, and `redirect=` SPF flagged as "no all mechanism") are
    separate and fixed in that file's own pass. This change only makes the
    underlying records available.

· Timeouts (finding #4)
    process.run_cmd returns partial output on timeout now, so a slow dnsx
    run contributes what it resolved instead of returning nothing.
"""

import json
import shutil
from pathlib import Path

from modules.utils.process import run_cmd
from modules.utils.output  import append_to_raw, write_clean, safe_print

# Common DKIM selectors seen across major providers. Queried against the
# apex only (per-host × per-selector would be far too many lookups).
_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "dkim",
    "mail", "smtp", "s1", "s2", "mandrill", "mxvault", "zoho",
    "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3",
    "dkim1", "key1", "sig1", "amazonses",
]


def run_zone_transfer(domain: str, out_dir: Path):
    """
    Attempt AXFR zone transfer against each NS. On success, write the
    discovered names to _zone.txt so merge_subdomains folds them in.
    """
    raw_file  = out_dir / "subdomains_raw.txt"
    zone_file = out_dir / "_zone.txt"

    if not shutil.which("dig"):
        safe_print("    [i] Zone transfer skipped — dig not installed")
        safe_print("        Install: sudo apt install dnsutils  (or bind-tools on RHEL/Alpine)")
        append_to_raw(raw_file, "zone_transfer", "dig not found\n")
        return

    ns_stdout, _, _ = run_cmd(["dig", "+short", "NS", domain], timeout=10)
    nameservers = sorted({ns.rstrip('.') for ns in ns_stdout.splitlines() if ns.strip()})

    if not nameservers:
        append_to_raw(raw_file, "zone_transfer", "No NS records found\n")
        return

    found = set()
    for ns in nameservers:
        stdout, stderr, rc = run_cmd(
            ["dig", f"@{ns}", domain, "AXFR", "+noall", "+answer",
             "+time=5", "+tries=1"], timeout=20)
        append_to_raw(raw_file, f"zone_transfer_{ns}", stdout + stderr)

        if rc == 0 and stdout.strip() and "Transfer failed" not in stdout \
                and "connection timed out" not in stdout.lower():
            names = set()
            for line in stdout.splitlines():
                parts = line.split()
                if parts:
                    name = parts[0].rstrip('.').lower()
                    if name.endswith(f'.{domain}') or name == domain:
                        names.add(name)
            if names:
                safe_print(f"    [!] Zone transfer SUCCESS on {ns} — {len(names)} names")
                found.update(names)

    if found:
        existing = set()
        if zone_file.exists():
            with open(zone_file, 'r', errors='replace') as fh:
                existing = {l.strip() for l in fh if l.strip()}
        write_clean(zone_file, existing | found)
    else:
        safe_print("    [i] Zone transfer: refused by all nameservers (expected)")


# ── Email-authentication probe targets (DMARC / DKIM) ─────────────────────────

def _email_probe_targets(domain: str, hosts: list) -> list:
    """
    Build the list of names to resolve for email-auth analysis:
      · _dmarc.<host> for every target host
      · <selector>._domainkey.<apex> for common DKIM selectors
    """
    targets = set()
    for h in hosts:
        h = h.strip().lower().rstrip('.')
        if h:
            targets.add(f"_dmarc.{h}")
    for sel in _DKIM_SELECTORS:
        targets.add(f"{sel}._domainkey.{domain}")
    return sorted(targets)


def _resolve_email_txt(domain: str, hosts: list, out_dir: Path,
                       cfg: dict, threads: int) -> list:
    """
    Resolve DMARC/DKIM TXT records. Returns dns_records-formatted lines:
        <host> TXT "<value>"
    which is exactly what analyse_email_security() parses.
    """
    targets = _email_probe_targets(domain, hosts)
    if not targets:
        return []

    import tempfile
    tf = tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                     delete=False, prefix='rr_email_')
    try:
        tf.write('\n'.join(targets) + '\n')
        tf.close()

        resolvers = cfg.get('resolvers', './resolvers.txt')
        resolver_args = ["-r", resolvers] if Path(resolvers).exists() else []

        stdout, stderr, _ = run_cmd([
            "dnsx", "-l", tf.name, "-silent",
            "-t", str(threads),
            "-txt", "-resp", "-json",
        ] + resolver_args, timeout=300)
        append_to_raw(out_dir / "subdomains_raw.txt", "dnsx_email_auth", stderr)

        lines = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = rec.get("host", "").lower().rstrip(".")
            for txt in rec.get("txt", []):
                lines.append(f'{host} TXT "{txt}"')
        return lines
    finally:
        Path(tf.name).unlink(missing_ok=True)


def run_dns_resolution(domain: str, subs_file: Path,
                       out_dir: Path, cfg: dict, available: dict):
    """Resolve all targets, extracting every record type, plus DMARC/DKIM."""
    raw_file = out_dir / "subdomains_raw.txt"

    if not available.get("dnsx"):
        msg = "dnsx not installed — DNS resolution skipped\n"
        safe_print(f"    [!] {msg.strip()}")
        append_to_raw(raw_file, "dnsx_resolve", msg)
        return

    threads   = cfg.get('brute_threads', cfg.get('threads', 100))
    resolvers = cfg.get('resolvers', './resolvers.txt')

    with open(subs_file, 'r', errors='replace') as fh:
        target_hosts = [l.strip() for l in fh if l.strip()]
    sub_count = len(target_hosts)

    safe_print(f"    [>] dnsx resolving {sub_count:,} targets ...", end='', flush=True)

    resolver_args = ["-r", resolvers] if Path(resolvers).exists() else []
    stdout, stderr, _ = run_cmd([
        "dnsx", "-l", str(subs_file), "-silent",
        "-t", str(threads),
        "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
        "-resp", "-json",
    ] + resolver_args, timeout=600)

    append_to_raw(raw_file, "dnsx_resolve", stderr)

    resolved_pairs, all_ips, cname_pairs, dns_lines = [], set(), [], []

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

    safe_print(f" {len(all_ips)} unique IPs")

    # ── DMARC / DKIM records (finding #6, data half) ──────────────────────────
    safe_print("    [>] Querying _dmarc + DKIM selector records ...",
               end='', flush=True)
    email_lines = _resolve_email_txt(domain, target_hosts, out_dir, cfg, threads)
    dns_lines.extend(email_lines)
    safe_print(f" {len(email_lines)} email-auth TXT records")

    write_clean(out_dir / "resolved.txt",    resolved_pairs)
    write_clean(out_dir / "ips.txt",         all_ips)
    write_clean(out_dir / "dns_records.txt", dns_lines)
    if cname_pairs:
        write_clean(out_dir / "cnames.txt", cname_pairs)

    safe_print(f"    [+] resolved.txt:    {len(resolved_pairs)} entries")
    if cname_pairs:
        safe_print(f"    [+] cnames.txt:      {len(cname_pairs)} CNAME records  "
                   f"← review for subdomain takeover")
    safe_print(f"    [+] dns_records.txt: {len(dns_lines)} total records")
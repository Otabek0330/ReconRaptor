"""
modules/core/reporter.py

Generates report.md per domain after all phases complete.

What this version adds vs the previous one
──────────────────────────────────────────
· Surfaces the cloud-vs-CDN split from enrichment.py (finding #24): the CDN
  count is now true CDNs only, and cloud-hosted IPs (origin likely
  reachable) get their own summary row and tag.
· Surfaces ips_private.txt as an internal-exposure finding — private/
  loopback IPs that appeared in the target's public DNS records.
"""

import json
from pathlib import Path
from datetime import datetime


def _read_lines(path: Path) -> list:
    if not path.exists():
        return []
    return [l for l in path.read_text(errors='replace').splitlines() if l.strip()]


def generate_report(domain: str, out_dir: Path) -> Path:
    out_dir     = Path(out_dir)
    report_file = out_dir / "report.md"
    now         = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    subs        = _read_lines(out_dir / "subdomains.txt")
    alive       = _read_lines(out_dir / "alive.txt")
    ips         = _read_lines(out_dir / "ips.txt")
    private_ips = _read_lines(out_dir / "ips_private.txt")
    paths       = _read_lines(out_dir / "traversal.txt")
    cnames      = _read_lines(out_dir / "cnames.txt")
    dns_recs    = _read_lines(out_dir / "dns_records.txt")
    ports       = _read_lines(out_dir / "open_ports.txt")

    email_findings = _read_lines(out_dir / "extras" / "email_security.txt")
    web_paths      = _read_lines(out_dir / "extras" / "web_paths.txt")

    # IP enrichment — count true CDNs and cloud-hosted separately.
    cdn_count = cloud_count = 0
    enrich_rows = []
    enrich_file = out_dir / "ip_enrichment.json"
    if enrich_file.exists():
        try:
            data = json.loads(enrich_file.read_text())
            for ip, d in sorted(data.items()):
                cdn   = d.get('cdn') or ''
                cloud = d.get('cloud') or ''
                if cdn:
                    cdn_count += 1
                    tag = f"  [CDN: {cdn}]"
                elif cloud:
                    cloud_count += 1
                    tag = f"  [cloud: {cloud}]"
                else:
                    tag = ""
                enrich_rows.append(
                    f"{ip:<18} {d.get('country','?')}/{d.get('city','?')}  "
                    f"{d.get('as','')}{tag}")
        except (json.JSONDecodeError, KeyError):
            pass

    ports_json = {}
    pj_file    = out_dir / "ports.json"
    if pj_file.exists():
        try:
            ports_json = json.loads(pj_file.read_text())
        except Exception:
            pass

    def section(title: str) -> str:
        return f"\n## {title}\n"

    def code_block(lines: list, cap: int = 100, see_file: str = '') -> str:
        shown = lines[:cap]
        tail  = ([f"… {len(lines)-cap} more — see {see_file}"]
                 if len(lines) > cap and see_file else [])
        return "```\n" + "\n".join(shown + tail) + "\n```\n"

    L = [
        f"# Recon Raptor — {domain}",
        "",
        f"Generated: {now}",
        "",
        "## Summary",
        "",
        "| Metric                     | Count |",
        "|----------------------------|-------|",
        f"| Subdomains discovered      | {len(subs)} |",
        f"| Live hosts (HTTP/S)        | {len(alive)} |",
        f"| Unique public IPs          | {len(ips)} |",
        f"| CDN / WAF fronted IPs      | {cdn_count} |",
        f"| Cloud-hosted IPs           | {cloud_count} |",
        f"| Private/internal IPs (exposure) | {len(private_ips)} |",
        f"| Open ports                 | {len(ports)} |",
        f"| CNAME records              | {len(cnames)} |",
        f"| DNS records (total)        | {len(dns_recs)} |",
        f"| Paths discovered           | {len(paths)} |",
        f"| Target-specific paths      | {len(web_paths)} |",
        f"| Email security findings    | {len(email_findings)} |",
        "",
    ]

    if private_ips:
        L += [
            section(f"⚠️  Internal IP Exposure ({len(private_ips)})"),
            "> Private / loopback addresses found in this target's public DNS "
            "records. These disclose internal network structure and should not "
            "resolve publicly.",
            "",
            code_block(private_ips, 100, "ips_private.txt"),
        ]

    if subs:
        L += [section(f"Subdomains ({len(subs)})"),
              code_block(subs, 150, "subdomains.txt")]

    if alive:
        L += [section(f"Live Hosts ({len(alive)})"),
              code_block(alive, 80, "alive.txt")]

    if ports_json:
        L += [section(f"Open Ports ({len(ports)} total across {len(ports_json)} IPs)")]
        port_lines = []
        for ip, port_list in sorted(ports_json.items()):
            port_lines.append(f"{ip:<18} {', '.join(str(p) for p in port_list)}")
        L += [code_block(port_lines, 100, "ports.json")]

    if cnames:
        L += [
            section(f"CNAME Records ({len(cnames)})"),
            "> ⚠️  Review for potential subdomain takeover — dangling CNAMEs "
            "pointing to unclaimed cloud/SaaS services.",
            "",
            code_block(cnames, 200, "cnames.txt"),
        ]

    if enrich_rows:
        L += [section(f"IP Enrichment ({len(ips)} IPs — "
                      f"{cdn_count} CDN, {cloud_count} cloud-hosted)"),
              code_block(enrich_rows, 100, "ip_enrichment.json")]

    if email_findings:
        critical = [f for f in email_findings if 'CRITICAL' in f or 'MISSING' in f]
        L += [section(f"Email Security ({len(email_findings)} findings, "
                      f"{len(critical)} critical/missing)"),
              code_block(email_findings, 50, "extras/email_security.txt")]

    if paths:
        L += [section(f"Directory Traversal ({len(paths)} paths)"),
              code_block(paths, 200, "traversal.txt")]

    if web_paths:
        L += [section(f"Target-specific Paths from robots.txt / Sitemaps ({len(web_paths)})"),
              code_block(web_paths, 50, "extras/web_paths.txt")]

    L += [
        "---",
        "_Generated by Recon Raptor_",
    ]

    report_file.write_text('\n'.join(L))
    safe_count = (f"{len(subs)} subs · {len(alive)} alive · "
                  f"{len(ports)} ports · {len(paths)} paths")
    print(f"    [+] report.md  ({safe_count})")
    return report_file
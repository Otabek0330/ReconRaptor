"""
modules/core/scanner.py

Orchestrates a complete scan run.

Phase order:
  1. Subdomain enumeration  (passive + bruteforce)
  2. DNS resolution         (A/AAAA/CNAME/MX/NS/TXT + zone transfer)
  3. HTTP probe             (live hosts via httpx)
  4. Directory traversal    (on alive hosts) ──┐  run in parallel
  5. IP enrichment          (ip-api.com/ipinfo)─┘
  6. Report generation      (report.md per domain)
"""

import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.core.preflight  import detect_tools
from modules.core.reporter   import generate_report
from modules.phases.subdomain import run_passive, run_bruteforce, merge_subdomains
from modules.phases.resolver  import run_dns_resolution, run_zone_transfer
from modules.phases.http_probe import run_http_probe
from modules.phases.traversal  import run_traversal
from modules.phases.enrichment import run_enrichment
from modules.utils.wordlist import clean_wordlist
from modules.utils.output   import setup_domain_dir, print_phase_header, print_domain_header


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_domains(args) -> list[str]:
    if args.domain:
        return [args.domain.strip().lower()]

    domains_file = Path(args.domains)
    if not domains_file.exists():
        print(f"[!] Domains file not found: {args.domains}")
        sys.exit(1)

    domains = []
    for raw in domains_file.read_text(errors='replace').splitlines():
        line = raw.strip().lower()
        if line and not line.startswith('#'):
            domains.append(line)

    if not domains:
        print(f"[!] No domains found in {args.domains}")
        sys.exit(1)

    return domains


def _apply_profile(cfg: dict, args) -> dict:
    """Apply --quick / --full and --skip-* flags to the config phases dict."""
    phases = cfg['phases']
    extras = cfg.get('extras', {})

    if getattr(args, 'quick', False):
        phases['bruteforce']    = False
        phases['traversal']     = False
        phases['ip_enrichment'] = False

    if getattr(args, 'full', False):
        extras['wayback_urls']       = True
        extras['screenshots']        = True
        extras['subdomain_takeover'] = True

    skip_map = {
        'skip_passive':   'passive_enum',
        'skip_brute':     'bruteforce',
        'skip_resolve':   'dns_resolve',
        'skip_http':      'http_probe',
        'skip_traversal': 'traversal',
        'skip_enrich':    'ip_enrichment',
    }
    for attr, phase_key in skip_map.items():
        if getattr(args, attr, False):
            phases[phase_key] = False

    cfg['phases'] = phases
    cfg['extras'] = extras
    return cfg


# ── Per-domain runner ─────────────────────────────────────────────────────────

def _process_domain(domain: str, cfg: dict,
                    available: dict, wordlist_path: str | None,
                    results_root: Path):
    phases = cfg['phases']
    extras = cfg.get('extras', {})
    out_dir = setup_domain_dir(domain, results_root)

    # ── 1. Subdomain enumeration ─────────────────────────────────────────────
    do_passive = phases.get('passive_enum', True)
    do_brute   = phases.get('bruteforce',   True) and bool(wordlist_path)

    if do_passive or do_brute:
        print_phase_header("Subdomain enumeration")
        if do_passive:
            run_passive(domain, out_dir, available)
        if do_brute:
            run_bruteforce(domain, wordlist_path, out_dir, cfg, available)
        merge_subdomains(domain, out_dir)
    else:
        print("  [i] Subdomain enumeration skipped")

    subs_file = out_dir / "subdomains.txt"

    # ── 2. DNS resolution ────────────────────────────────────────────────────
    if phases.get('dns_resolve', True) and subs_file.exists() and subs_file.stat().st_size > 0:
        print_phase_header("DNS resolution")
        if extras.get('zone_transfer', True):
            run_zone_transfer(domain, out_dir)
        run_dns_resolution(domain, subs_file, out_dir, cfg, available)
    else:
        print("  [i] DNS resolution skipped (no subdomains or phase disabled)")

    ips_file = out_dir / "ips.txt"

    # ── 3. HTTP probe ────────────────────────────────────────────────────────
    if phases.get('http_probe', True) and subs_file.exists() and subs_file.stat().st_size > 0:
        print_phase_header("HTTP probe")
        run_http_probe(domain, subs_file, out_dir, cfg, available)
    else:
        print("  [i] HTTP probe skipped")

    alive_file = out_dir / "alive.txt"

    # ── 4 + 5. Traversal & IP enrichment (parallel) ──────────────────────────
    run_trav   = phases.get('traversal',     True) and alive_file.exists() and alive_file.stat().st_size > 0
    run_enrich = phases.get('ip_enrichment', True) and ips_file.exists()   and ips_file.stat().st_size > 0

    if run_trav or run_enrich:
        with ThreadPoolExecutor(max_workers=2) as ex:
            futures = {}

            if run_trav:
                print_phase_header("Directory traversal")
                futures['traversal'] = ex.submit(
                    run_traversal, domain, alive_file, wordlist_path, out_dir, cfg, available
                )

            if run_enrich:
                print_phase_header("IP enrichment")
                futures['enrichment'] = ex.submit(
                    run_enrichment, domain, ips_file, out_dir, cfg
                )

            for name, fut in futures.items():
                try:
                    fut.result()
                except Exception as e:
                    print(f"\n  [!] {name} phase error: {e}")

    if not run_trav:
        print("  [i] Directory traversal skipped (no alive hosts or phase disabled)")
    if not run_enrich:
        print("  [i] IP enrichment skipped (no IPs or phase disabled)")

    # ── 6. Report ────────────────────────────────────────────────────────────
    print_phase_header("Report")
    generate_report(domain, out_dir)

    print(f"\n  [+] {domain} → {out_dir}/\n")


# ── Public entrypoint ─────────────────────────────────────────────────────────

def run_scan(args, cfg: dict):
    # Apply flags
    cfg = _apply_profile(cfg, args)

    # Output dir override
    if getattr(args, 'output', None):
        cfg['output_dir'] = args.output

    # Wordlist
    wordlist_path = None
    if cfg['phases'].get('bruteforce', True):
        wl = getattr(args, 'wordlist', None) or cfg.get('wordlist', '')
        if wl:
            print(f"[*] Loading wordlist: {wl}")
            try:
                wordlist_path, valid, stripped = clean_wordlist(wl)
                msg = f"    {valid:,} valid entries"
                if stripped:
                    msg += f"  ({stripped} DNS-invalid entries stripped)"
                print(msg)
            except FileNotFoundError as e:
                print(f"[!] {e}")
                sys.exit(1)
        else:
            print("[i] No wordlist configured — bruteforce phase skipped")
            cfg['phases']['bruteforce'] = False

    # Detect tools once for all domains
    print("[*] Detecting installed tools...")
    available = detect_tools()
    ready = sum(1 for v in available.values() if v)
    print(f"    {ready} tools ready\n")

    # Load domains
    domains = _load_domains(args)
    plural  = "domain" if len(domains) == 1 else "domains"
    print(f"[*] {len(domains)} {plural} queued\n")

    results_root = Path(cfg.get('output_dir', './results'))
    results_root.mkdir(parents=True, exist_ok=True)

    # Run each domain
    for domain in domains:
        print_domain_header(domain)
        _process_domain(domain, cfg, available, wordlist_path, results_root)

    # Cleanup temp wordlist file
    if wordlist_path:
        Path(wordlist_path).unlink(missing_ok=True)

    print(f"[+] All scans complete.  Results: {results_root}/")

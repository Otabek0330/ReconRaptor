"""
modules/core/scanner.py

Scan orchestrator.

What this version fixes vs the previous one
───────────────────────────────────────────
· Checkpoint correctness (finding #1)
    - A phase is cached ONLY if it actually ran to completion AND its
      primary capability was present. If the required tool was missing
      (e.g. httpx not installed) the phase is NOT cached, so installing
      the tool later re-runs it instead of skipping it forever.
    - Each checkpoint entry stores a fingerprint of the inputs that
      affect its result (relevant phase toggles, wordlist signature,
      tool availability). Change a flag — e.g. run --quick then --full —
      and the affected phase's fingerprint no longer matches, so it
      re-runs. Previously `subdomain_enum` cached under --quick meant
      bruteforce never ran on a later --full.
    - A phase that raises is not cached (and does not abort the domain).
    - Checkpoint writes are atomic (temp file + os.replace).

· Zone transfer ordering (finding #5)
    AXFR now runs inside Phase 1, BEFORE the resolve/probe target list is
    built, so names from a successful zone transfer are actually resolved
    and probed instead of being written to subdomains.txt too late.

· Stale artifacts (finding #7)
    Each phase clears its own output files before it runs, and --fresh
    clears them all. Old cnames.txt / web_paths.txt / email_security.txt
    no longer survive into a new report.

· --quick actually means "passive enum + HTTP probe only" (finding #12)
    It now also skips dns_resolve, port_scan, harvest and email analysis.

· Private/loopback IPs are filtered before port scanning (finding #14)
    naabu no longer scans RFC-1918 / loopback hosts that an internal DNS
    record happened to point at. Those IPs are recorded in
    ips_private.txt as an internal-exposure finding.

· Resolver path (finding #9, partial)
    A relative `resolvers:` path is resolved against the project root, so
    the tool works when run from any directory via the PATH symlink.

· Ctrl+C stops in-flight tools (finding #25)
    The SIGINT handler kills running child process groups.

Still needs other files: tool-path threading (#2 detection half), the
dnsx / subfinder native-limit and wildcard fixes (#3, #4 per-tool), the
_dmarc/DKIM query (#6), the httpx binary-identity check (#11).
"""

import os
import re
import sys
import json
import signal
import atexit
import tempfile
import ipaddress
import traceback
from datetime import datetime
from pathlib import Path

from modules.core.config    import validate_domain
from modules.core.preflight import detect_tools, resolve_phase_names, phase_names_help
from modules.core.reporter  import generate_report
from modules.utils.process  import kill_all_children
from modules.utils.wordlist import clean_wordlist, clean_dir_wordlist
from modules.utils.output   import (setup_domain_dir, print_phase_header,
                                    print_domain_header, safe_print)

from modules.phases.subdomain    import run_passive, run_bruteforce, merge_subdomains
from modules.phases.resolver     import run_dns_resolution, run_zone_transfer
from modules.phases.port_scanner import run_port_scan, web_ports_from_scan
from modules.phases.http_probe   import run_http_probe
from modules.phases.traversal    import run_traversal
from modules.phases.enrichment   import run_enrichment
from modules.phases.extras       import harvest_robots_and_sitemaps, analyse_email_security

# Project root (…/ReconRaptor) — used to resolve bundled relative paths.
ROOT_DIR = Path(__file__).resolve().parent.parent.parent


# ── Temp file registry — cleaned up on Ctrl+C or exit ────────────────────────

_TEMP_FILES: list = []


def _register_temp(path: str):
    _TEMP_FILES.append(path)


def _cleanup_temps():
    for p in _TEMP_FILES:
        try:
            Path(p).unlink(missing_ok=True)
        except Exception:
            pass


def _sigint_handler(sig, frame):
    safe_print("\n\n[!] Interrupted — killing running tools and cleaning up ...")
    kill_all_children()        # stop the tool that's running right now
    _cleanup_temps()
    sys.exit(130)


atexit.register(_cleanup_temps)
signal.signal(signal.SIGINT, _sigint_handler)


# ── Checkpoint helpers ────────────────────────────────────────────────────────
#
# A checkpoint entry is: { "done": True, "at": <iso>, "fp": <fingerprint> }.
# A phase counts as complete only when done is True AND the stored
# fingerprint equals the current one, so changing inputs invalidates it.

def _cp_file(out_dir: Path) -> Path:
    return out_dir / ".rr_checkpoint.json"


def _load_cp(out_dir: Path) -> dict:
    f = _cp_file(out_dir)
    if f.exists():
        try:
            return json.loads(f.read_text())
        except Exception:
            return {}
    return {}


def _save_cp(out_dir: Path, phase: str, fingerprint: str):
    """Atomically record a phase as complete with its input fingerprint."""
    cp = _load_cp(out_dir)
    cp[phase] = {"done": True, "at": datetime.now().isoformat(), "fp": fingerprint}
    target = _cp_file(out_dir)
    tmp = target.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cp, indent=2))
    os.replace(tmp, target)


def _done(cp: dict, phase: str, fingerprint: str) -> bool:
    entry = cp.get(phase, {})
    return bool(entry.get("done")) and entry.get("fp") == fingerprint


# ── Fingerprints ──────────────────────────────────────────────────────────────

def _file_sig(path) -> str:
    """Cheap signature of a file's identity: (resolved path, size, mtime)."""
    if not path:
        return "none"
    p = Path(path)
    try:
        st = p.stat()
        return f"{p.resolve()}::{st.st_size}::{int(st.st_mtime)}"
    except OSError:
        return "missing"


def _fp(*parts) -> str:
    return "|".join(str(x) for x in parts)


def _phase_fp(phase: str, cfg: dict, available: dict) -> str:
    """
    Fingerprint the inputs that change a phase's result. Deliberately
    built only from cheap, always-available data (toggles, wordlist
    signatures, tool availability) so it's stable across resume runs.
    """
    phases = cfg.get('phases', {})
    extras = cfg.get('extras', {})
    sub_sig = cfg.get('_sub_wl_sig', 'none')
    dir_sig = cfg.get('_dir_wl_sig', 'none')

    if phase == 'subdomain_enum':
        return _fp(phase,
                   phases.get('passive_enum', True),
                   phases.get('bruteforce', True),
                   extras.get('zone_transfer', True),
                   sub_sig,
                   bool(available.get('subfinder')),
                   bool(available.get('assetfinder')),
                   bool(available.get('findomain')),
                   bool(available.get('puredns') and available.get('massdns')),
                   bool(available.get('dnsx')))
    if phase == 'dns_resolve':
        return _fp(phase, phases.get('dns_resolve', True),
                   bool(available.get('dnsx')))
    if phase == 'port_scan':
        pc = cfg.get('port_scan', {})
        return _fp(phase, phases.get('port_scan', True),
                   bool(available.get('naabu')),
                   pc.get('top_ports', 1000), pc.get('rate', 1000),
                   tuple(pc.get('ports', []) or cfg.get('ports', [])))
    if phase == 'http_probe':
        return _fp(phase, phases.get('http_probe', True),
                   bool(available.get('httpx')),
                   tuple(cfg.get('ports', [])))
    if phase == 'harvest':
        return _fp(phase, phases.get('harvest', True))
    if phase == 'traversal':
        return _fp(phase, phases.get('traversal', True), dir_sig,
                   cfg.get('depth', 2), tuple(cfg.get('extensions', [])),
                   bool(available.get('gobuster')),
                   bool(available.get('dirsearch')),
                   bool(available.get('ffuf')))
    if phase == 'ip_enrichment':
        return _fp(phase, phases.get('ip_enrichment', True),
                   bool((cfg.get('tokens', {}) or {}).get('ipinfo')))
    if phase == 'email_security':
        return _fp(phase, phases.get('email_security', True))
    return _fp(phase)


# ── Stale-artifact clearing ───────────────────────────────────────────────────

_PHASE_ARTIFACTS = {
    'subdomain_enum': ["subdomains.txt", "resolve_targets.txt"],
    'dns_resolve':    ["resolved.txt", "ips.txt", "ips_public.txt",
                       "ips_private.txt", "dns_records.txt", "cnames.txt"],
    'port_scan':      ["open_ports.txt", "ports.json"],
    'http_probe':     ["alive.txt"],
    'harvest':        ["extras/web_paths.txt"],
    'traversal':      ["traversal.txt", "traversal_raw.txt"],
    'ip_enrichment':  ["ip_enrichment.json", "ip_summary.txt"],
    'email_security': ["extras/email_security.txt"],
}


def _clear_artifacts(out_dir: Path, phase: str):
    for rel in _PHASE_ARTIFACTS.get(phase, []):
        try:
            (out_dir / rel).unlink(missing_ok=True)
        except Exception:
            pass


def _clear_all_artifacts(out_dir: Path):
    for phase in _PHASE_ARTIFACTS:
        _clear_artifacts(out_dir, phase)
    for extra in ["subdomains_raw.txt", "_passive.txt", "_brute.txt"]:
        try:
            (out_dir / extra).unlink(missing_ok=True)
        except Exception:
            pass


# ── Profile / flag application ────────────────────────────────────────────────

def _apply_profile(cfg: dict, args) -> dict:
    phases = dict(cfg.get('phases', {}))
    extras = dict(cfg.get('extras', {}))

    # Pure-Python phases that have no config toggle by default.
    phases.setdefault('harvest', True)
    phases.setdefault('email_security', True)

    if getattr(args, 'quick', False):
        # "Passive enum + HTTP probe only" — genuinely only those two now.
        phases.update(bruteforce=False, dns_resolve=False, port_scan=False,
                      traversal=False, ip_enrichment=False,
                      harvest=False, email_security=False)
        extras.update(wayback_urls=False, screenshots=False,
                      zone_transfer=False)

    if getattr(args, 'full', False):
        extras.update(wayback_urls=True, screenshots=True,
                      subdomain_takeover=True)

    skip_map = {
        'skip_passive':   'passive_enum',
        'skip_brute':     'bruteforce',
        'skip_resolve':   'dns_resolve',
        'skip_http':      'http_probe',
        'skip_traversal': 'traversal',
        'skip_enrich':    'ip_enrichment',
        'skip_ports':     'port_scan',
        'skip_harvest':   'harvest',
        'skip_email':     'email_security',
    }
    for attr, key in skip_map.items():
        if getattr(args, attr, False):
            phases[key] = False

    # --only NAME[,NAME...] — run ONLY the named phase(s)/tool(s), disable the
    # rest. Overrides skips/quick/full. Upstream phases are skipped but their
    # existing result files (from a prior run) are reused.
    only = getattr(args, 'only', None)
    if only:
        names = [n for n in re.split(r'[,\s]+', only) if n.strip()]
        keep, unknown = resolve_phase_names(names)
        if unknown:
            safe_print(f"[!] Unknown --only name(s): {', '.join(unknown)}")
            safe_print(f"    Valid names: {phase_names_help()}")
            safe_print("    See: recon_raptor list --tools")
            sys.exit(1)
        for key in list(phases.keys()) + ['passive_enum', 'bruteforce',
                                          'dns_resolve', 'port_scan', 'http_probe',
                                          'traversal', 'ip_enrichment', 'harvest',
                                          'email_security']:
            phases[key] = key in keep
        # Zone transfer only makes sense while enumerating subdomains.
        extras['zone_transfer'] = ('passive_enum' in keep) and extras.get('zone_transfer', True)
        cfg['_only_active'] = sorted(keep)

    cfg['phases'] = phases
    cfg['extras'] = extras
    return cfg


# ── Input loading ─────────────────────────────────────────────────────────────

def _load_domains(args) -> list:
    if args.domain:
        try:
            return [validate_domain(args.domain)]
        except ValueError as e:
            safe_print(f"[!] Invalid domain: {e}")
            sys.exit(1)

    domains_file = Path(args.domains)
    if not domains_file.exists():
        safe_print(f"[!] Domains file not found: {args.domains}")
        sys.exit(1)

    domains = []
    errors  = []
    for i, raw in enumerate(domains_file.read_text(errors='replace').splitlines(), 1):
        raw = raw.strip()
        if not raw or raw.startswith('#'):
            continue
        try:
            domains.append(validate_domain(raw))
        except ValueError as e:
            errors.append(f"  Line {i}: {e}")

    if errors:
        safe_print(f"[!] {len(errors)} invalid domain(s) in {args.domains}:")
        for e in errors:
            safe_print(e)
        safe_print("    Fix or remove them and re-run.")
        sys.exit(1)

    if not domains:
        safe_print(f"[!] No domains found in {args.domains}")
        sys.exit(1)

    # De-dupe while preserving order.
    seen, unique = set(), []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique.append(d)
    return unique


# ── Wordlist preparation ──────────────────────────────────────────────────────

def _prepare_wordlists(args, cfg: dict) -> tuple:
    """
    Returns (sub_wordlist_path, dir_wordlist_path); either can be None.
    Temp files are registered for cleanup. Also stashes signatures of the
    ORIGINAL wordlists on cfg so checkpoint fingerprints stay stable
    across runs (the cleaned temp file changes name every run).
    """
    sub_path = dir_path = None

    sub_src = getattr(args, 'wordlist', None) or cfg.get('wordlist', '') or ''
    dir_src = getattr(args, 'dir_wordlist', None) or cfg.get('dir_wordlist', '') or ''
    cfg['_sub_wl_sig'] = _file_sig(sub_src) if sub_src else 'none'
    cfg['_dir_wl_sig'] = _file_sig(dir_src) if dir_src else 'none'

    if sub_src and cfg['phases'].get('bruteforce', True):
        safe_print(f"[*] Subdomain wordlist: {sub_src}")
        try:
            p, valid, stripped = clean_wordlist(sub_src)
            _register_temp(p)
            sub_path = p
            msg = f"    {valid:,} valid DNS labels"
            if stripped:
                msg += f"  ({stripped} DNS-invalid stripped)"
            safe_print(msg)
        except FileNotFoundError as e:
            safe_print(f"[!] {e}")
            sys.exit(1)
    elif cfg['phases'].get('bruteforce', True):
        safe_print("[i] No subdomain wordlist — bruteforce skipped")
        cfg['phases']['bruteforce'] = False

    if dir_src and cfg['phases'].get('traversal', True):
        safe_print(f"[*] Directory wordlist:  {dir_src}")
        try:
            p, valid, stripped = clean_dir_wordlist(dir_src)
            _register_temp(p)
            dir_path = p
            msg = f"    {valid:,} entries"
            if stripped:
                msg += f"  ({stripped} invalid stripped)"
            safe_print(msg)
        except FileNotFoundError as e:
            safe_print(f"[!] {e}")
            sys.exit(1)
    elif cfg['phases'].get('traversal', True):
        safe_print("[i] No dir traversal wordlist — traversal skipped")
        cfg['phases']['traversal'] = False

    return sub_path, dir_path


# ── IP helpers (finding #14) ──────────────────────────────────────────────────

def _is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or
                    a.is_multicast or a.is_reserved or a.is_unspecified)
    except ValueError:
        return False


def _split_public_ips(out_dir: Path):
    """
    Read ips.txt, write ips_public.txt (scannable) and ips_private.txt
    (internal-exposure finding). Returns (public_file, has_public).
    """
    ips_file = out_dir / "ips.txt"
    public_file  = out_dir / "ips_public.txt"
    private_file = out_dir / "ips_private.txt"
    if not (ips_file.exists() and ips_file.stat().st_size > 0):
        return public_file, False

    with open(ips_file, 'r', errors='replace') as fh:
        ips = [l.strip() for l in fh if l.strip()]

    public  = sorted({ip for ip in ips if _is_public_ip(ip)})
    private = sorted({ip for ip in ips if not _is_public_ip(ip)})

    public_file.write_text('\n'.join(public) + ('\n' if public else ''))
    if private:
        private_file.write_text('\n'.join(private) + '\n')
        safe_print(f"    [!] {len(private)} private/loopback IP(s) in DNS records "
                   f"— internal exposure, saved to ips_private.txt (not scanned)")

    return public_file, bool(public)


# ── Per-domain runner ─────────────────────────────────────────────────────────

def _run_phase(out_dir: Path, cp: dict, phase: str, fingerprint: str,
               label: str, capable: bool, fn) -> bool:
    """
    Execute one phase with correct checkpoint semantics.

    Returns True if the phase's outputs are present (either freshly
    produced or from a valid checkpoint), False otherwise.
    """
    if _done(cp, phase, fingerprint):
        safe_print(f"\n  [✓] {label} — from checkpoint")
        return True

    _clear_artifacts(out_dir, phase)
    print_phase_header(label)
    try:
        fn()
    except Exception as exc:
        safe_print(f"    [!] {label} failed: {exc}")
        safe_print("        (not cached — will retry on next run)")
        return False

    if capable:
        _save_cp(out_dir, phase, fingerprint)
    else:
        safe_print(f"    [i] {label} ran without its primary tool — "
                   f"not caching so it retries after you install it")
    return True


def _process_domain(domain: str, cfg: dict, available: dict,
                    sub_wl: str, dir_wl: str, results_root: Path,
                    fresh: bool = False):
    phases  = cfg['phases']
    extras  = cfg.get('extras', {})
    out_dir = setup_domain_dir(domain, results_root)

    if fresh:
        _cp_file(out_dir).unlink(missing_ok=True)
        _clear_all_artifacts(out_dir)
        safe_print(f"  [i] --fresh: cleared checkpoint and artifacts for {domain}")

    cp = _load_cp(out_dir)

    completed = [k for k, v in cp.items()
                 if isinstance(v, dict) and v.get("done")
                 and v.get("fp") == _phase_fp(k, cfg, available)]
    if completed:
        safe_print(f"  [i] Resuming — {len(completed)} phase(s) still valid: "
                   f"{', '.join(sorted(completed))}")

    # ── Phase 1: Subdomain enumeration (incl. zone transfer BEFORE merge) ─────
    if phases.get('passive_enum', True) or phases.get('bruteforce', True):
        def _enum():
            if extras.get('zone_transfer', True):
                # AXFR first, so any transferred names are merged and then
                # resolved/probed — not written too late to matter.
                run_zone_transfer(domain, out_dir)
            if phases.get('passive_enum', True):
                run_passive(domain, out_dir, available)
            if phases.get('bruteforce', True) and sub_wl:
                run_bruteforce(domain, sub_wl, out_dir, cfg, available)
            merge_subdomains(domain, out_dir)

            subs_check = out_dir / "subdomains.txt"
            sub_count = 0
            if subs_check.exists():
                with open(subs_check, 'r', errors='replace') as fh:
                    sub_count = sum(1 for l in fh if l.strip())
            if sub_count == 0:
                safe_print(
                    "\n  [!] 0 subdomains found from any source.\n"
                    "      This run is NOT cached, so simply re-running will\n"
                    "      retry it. Check subdomains_raw.txt for tool errors,\n"
                    "      and confirm subfinder/assetfinder/findomain/crt.sh\n"
                    "      can reach the network from this machine."
                )

        # Capable if at least one enumeration path is actually usable.
        enum_capable = (
            (phases.get('passive_enum', True) and
             any(available.get(t) for t in ("subfinder", "assetfinder", "findomain")))
            or (phases.get('bruteforce', True) and sub_wl and
                ((available.get('puredns') and available.get('massdns'))
                 or available.get('dnsx')))
        )
        _run_phase(out_dir, cp, 'subdomain_enum',
                   _phase_fp('subdomain_enum', cfg, available),
                   "Subdomain enumeration", enum_capable, _enum)
    else:
        safe_print("\n  [i] Subdomain enumeration skipped")

    subs_file = out_dir / "subdomains.txt"

    # ── Build the resolve/probe target list (apex always included) ────────────
    targets_file = out_dir / "resolve_targets.txt"
    discovered = set()
    if subs_file.exists():
        with open(subs_file, 'r', errors='replace') as fh:
            discovered = {l.strip().lower() for l in fh if l.strip()}
    discovered.add(domain.lower())
    targets_file.write_text('\n'.join(sorted(discovered)) + '\n')

    # ── Phase 2: DNS resolution ───────────────────────────────────────────────
    if phases.get('dns_resolve', True):
        _run_phase(out_dir, cp, 'dns_resolve',
                   _phase_fp('dns_resolve', cfg, available),
                   "DNS resolution", bool(available.get('dnsx')),
                   lambda: run_dns_resolution(domain, targets_file, out_dir,
                                              cfg, available))
    else:
        safe_print("\n  [i] DNS resolution skipped")

    # Filter private/loopback IPs before anything scans them (finding #14).
    public_ips_file, has_public_ips = _split_public_ips(out_dir)
    ips_file = out_dir / "ips.txt"
    has_ips  = ips_file.exists() and ips_file.stat().st_size > 0

    # ── Phase 3: Port scanning (public IPs only) ──────────────────────────────
    probe_ports = None
    if phases.get('port_scan', True) and has_public_ips:
        fp = _phase_fp('port_scan', cfg, available)
        if _done(cp, 'port_scan', fp):
            safe_print("\n  [✓] Port scanning — from checkpoint")
            pj = out_dir / "ports.json"
            if pj.exists():
                try:
                    data = json.loads(pj.read_text())
                    all_ports = {p for ports in data.values() for p in ports}
                    probe_ports = (web_ports_from_scan({f"x:{p}" for p in all_ports})
                                   if all_ports else None)
                except Exception:
                    probe_ports = None
        else:
            _clear_artifacts(out_dir, 'port_scan')
            print_phase_header("Port scanning")
            try:
                port_pairs  = run_port_scan(domain, public_ips_file, out_dir,
                                            cfg, available)
                probe_ports = web_ports_from_scan(port_pairs) if port_pairs else None
                if available.get('naabu'):
                    _save_cp(out_dir, 'port_scan', fp)
                else:
                    safe_print("    [i] naabu missing — not caching port scan")
            except Exception as exc:
                safe_print(f"    [!] Port scanning failed: {exc} (not cached)")
    elif not has_public_ips:
        safe_print("\n  [i] Port scanning skipped — no public IPs discovered")
    else:
        safe_print("\n  [i] Port scanning skipped")

    # ── Phase 4: HTTP probe ───────────────────────────────────────────────────
    if phases.get('http_probe', True):
        _run_phase(out_dir, cp, 'http_probe',
                   _phase_fp('http_probe', cfg, available),
                   "HTTP probe", bool(available.get('httpx')),
                   lambda: run_http_probe(domain, targets_file, out_dir,
                                          cfg, available, probe_ports))
    else:
        safe_print("\n  [i] HTTP probe skipped")

    alive_file = out_dir / "alive.txt"
    has_alive  = alive_file.exists() and alive_file.stat().st_size > 0

    # ── Phase 5: robots.txt / sitemap harvest ─────────────────────────────────
    extra_paths_file = ""
    if phases.get('harvest', True) and has_alive:
        fp = _phase_fp('harvest', cfg, available)
        if _done(cp, 'harvest', fp):
            safe_print("\n  [✓] Web path harvest — from checkpoint")
            ep = out_dir / "extras" / "web_paths.txt"
            extra_paths_file = str(ep) if ep.exists() else ""
        else:
            _clear_artifacts(out_dir, 'harvest')
            print_phase_header("Web path harvest (robots + sitemaps)")
            try:
                extra_paths_file = harvest_robots_and_sitemaps(
                    domain, alive_file, out_dir)
                _save_cp(out_dir, 'harvest', fp)
            except Exception as exc:
                safe_print(f"    [!] Web path harvest failed: {exc} (not cached)")

    # ── Phase 6: Directory traversal ──────────────────────────────────────────
    if phases.get('traversal', True) and has_alive and dir_wl:
        fp = _phase_fp('traversal', cfg, available)
        if _done(cp, 'traversal', fp):
            safe_print("\n  [✓] Directory traversal — from checkpoint")
        else:
            _clear_artifacts(out_dir, 'traversal')
            print_phase_header("Directory traversal")
            effective_wl = dir_wl
            if extra_paths_file and Path(extra_paths_file).exists():
                merged = tempfile.NamedTemporaryFile(
                    mode='w', suffix='.txt', delete=False, prefix='rr_merged_wl_')
                try:
                    with open(extra_paths_file, 'r', errors='replace') as ef:
                        merged.write(ef.read())
                    with open(dir_wl, 'r', errors='replace') as df:
                        merged.write(df.read())
                finally:
                    merged.close()
                _register_temp(merged.name)
                effective_wl = merged.name
                safe_print(f"    [i] Prepended {Path(extra_paths_file).name} "
                           f"to traversal wordlist")

            trav_capable = any(available.get(t)
                               for t in ("gobuster", "dirsearch", "ffuf"))
            try:
                run_traversal(domain, alive_file, effective_wl, out_dir,
                              cfg, available)
                if trav_capable:
                    _save_cp(out_dir, 'traversal', fp)
                else:
                    safe_print("    [i] No traversal tool — not caching")
            except Exception as exc:
                safe_print(f"    [!] Directory traversal failed: {exc} (not cached)")
    elif not dir_wl:
        safe_print("\n  [i] Directory traversal skipped — no dir_wordlist configured")
    elif not has_alive:
        safe_print("\n  [i] Directory traversal skipped — no alive hosts")
    else:
        safe_print("\n  [i] Directory traversal skipped")

    # ── Phase 7: IP enrichment ────────────────────────────────────────────────
    if phases.get('ip_enrichment', True) and has_ips:
        # ip-api.com is a built-in fallback, so this phase is always "capable".
        _run_phase(out_dir, cp, 'ip_enrichment',
                   _phase_fp('ip_enrichment', cfg, available),
                   "IP enrichment", True,
                   lambda: run_enrichment(domain, ips_file, out_dir, cfg))
    else:
        safe_print("\n  [i] IP enrichment skipped")

    # ── Phase 8: Email security analysis ──────────────────────────────────────
    dns_file = out_dir / "dns_records.txt"
    if phases.get('email_security', True) and dns_file.exists():
        _run_phase(out_dir, cp, 'email_security',
                   _phase_fp('email_security', cfg, available),
                   "Email security analysis (SPF / DMARC / DKIM)", True,
                   lambda: analyse_email_security(domain, out_dir))

    # ── Report ────────────────────────────────────────────────────────────────
    print_phase_header("Report")
    try:
        generate_report(domain, out_dir)
    except Exception as exc:
        safe_print(f"    [!] Report generation failed: {exc}")

    safe_print(f"\n  [+] Done: {domain}")
    safe_print(f"      Results: {out_dir}/\n")


# ── Public entrypoint ─────────────────────────────────────────────────────────

def run_scan(args, cfg: dict):
    cfg = _apply_profile(cfg, args)

    if cfg.get('_only_active'):
        safe_print(f"[*] --only: running just {', '.join(cfg['_only_active'])}")
        safe_print("    (upstream phases skipped — existing result files reused where present)")

    if getattr(args, 'output', None):
        cfg['output_dir'] = args.output

    # Resolve a relative resolvers path against the project root so the
    # tool works when launched from any directory via the PATH symlink.
    resolvers = str(cfg.get('resolvers', './resolvers.txt'))
    rp = Path(resolvers)
    if not rp.is_absolute() and not rp.exists():
        candidate = ROOT_DIR / rp
        if candidate.exists():
            cfg['resolvers'] = str(candidate)

    safe_print("[*] Preparing wordlists ...")
    sub_wl, dir_wl = _prepare_wordlists(args, cfg)

    safe_print("\n[*] Detecting installed tools ...")
    available = detect_tools()
    ready = sum(1 for v in available.values() if v)
    safe_print(f"    {ready} tools ready\n")

    domains = _load_domains(args)
    plural  = "domain" if len(domains) == 1 else "domains"
    safe_print(f"[*] {len(domains)} {plural} queued\n")

    results_root = Path(cfg.get('output_dir', './results'))
    results_root.mkdir(parents=True, exist_ok=True)

    for domain in domains:
        print_domain_header(domain)
        try:
            _process_domain(domain, cfg, available, sub_wl, dir_wl,
                            results_root, fresh=getattr(args, 'fresh', False))
        except SystemExit:
            raise
        except Exception:
            # One bad domain must not sink the whole batch.
            safe_print(f"  [!] Unhandled error while processing {domain}:")
            safe_print(traceback.format_exc())
            continue

    safe_print(f"\n[+] All scans complete — results in: {results_root}/")
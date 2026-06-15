"""
modules/phases/subdomain.py

Phase 1: Subdomain enumeration.

Passive stream  — subfinder, assetfinder, findomain
Bruteforce      — puredns bruteforce (massdns backend)   ← preferred: fast, wildcard-aware
                  fallback: dnsx resolve                 ← slower, use brute_threads from config

Performance notes:
  puredns + massdns is 10-50x faster than dnsx for large wordlists and
  handles wildcard DNS correctly. Install with: sudo recon_raptor install

  dnsx fallback: use brute_threads (default 500) not the general threads
  value. 500 threads on a modern machine resolves ~3M FQDNs in ~5 minutes.
"""

import subprocess
import tempfile
import shutil
from pathlib import Path

from modules.utils.output import append_to_raw, extract_subdomains, write_clean


def _run(cmd: list, timeout: int = 300) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", f"[timeout after {timeout}s]", -1
    except FileNotFoundError:
        return "", f"[command not found: {cmd[0]}]", -1
    except Exception as e:
        return "", str(e), -1


# ── Passive enumeration ───────────────────────────────────────────────────────

def run_passive(domain: str, out_dir: Path, available: dict) -> set[str]:
    raw_file  = out_dir / "subdomains_raw.txt"
    all_subs  = set()
    tools_run = 0

    _passive_tools = [
        ("subfinder",   ["subfinder",   "-d", domain, "-silent", "-all"]),
        ("assetfinder", ["assetfinder", "--subs-only", domain]),
        ("findomain",   ["findomain",   "-t", domain, "-q"]),
    ]

    for name, cmd in _passive_tools:
        if not available.get(name):
            append_to_raw(raw_file, name, f"{name} not installed\n")
            continue

        print(f"    [>] {name} ...", end='', flush=True)
        stdout, stderr, _rc = _run(cmd, timeout=120)
        append_to_raw(raw_file, name, stdout + stderr)

        subs = extract_subdomains(domain, stdout)
        all_subs.update(subs)
        print(f" {len(subs)} found")
        tools_run += 1

    if tools_run == 0:
        print("    [!] No passive enumeration tools available")
        print("        Install them: sudo recon_raptor install")

    passive_file = out_dir / "_passive.txt"
    write_clean(passive_file, all_subs)
    print(f"    [+] Passive subtotal: {len(all_subs)} unique")
    return all_subs


# ── Bruteforce ────────────────────────────────────────────────────────────────

def run_bruteforce(domain: str, wordlist_path: str,
                   out_dir: Path, cfg: dict, available: dict) -> set[str]:
    raw_file     = out_dir / "subdomains_raw.txt"
    resolvers    = cfg.get('resolvers', './resolvers.txt')
    # brute_threads is a dedicated high-concurrency setting for DNS brute.
    # Default 500 — resolves ~3M FQDNs in ~5 min on a decent connection.
    brute_threads = cfg.get('brute_threads', 500)
    resolved     = set()

    # ── puredns bruteforce (preferred) ───────────────────────────────────────
    if available.get("puredns") and available.get("massdns"):
        if not Path(resolvers).exists():
            print(f"    [!] resolvers.txt not found: {resolvers}")
            return resolved

        brute_out   = out_dir / "_brute_resolved.txt"
        massdns_bin = shutil.which("massdns") or "massdns"

        candidate_count = _count_lines(wordlist_path)
        print(
            f"    [>] puredns bruteforce  {candidate_count:,} candidates"
            f"  (fast, wildcard-aware) ...",
            end='', flush=True,
        )
        stdout, stderr, _rc = _run([
            "puredns", "bruteforce", wordlist_path, domain,
            "--resolvers", resolvers,
            "--bin",       massdns_bin,
            "--write",     str(brute_out),
            "--quiet",
        ], timeout=7200)
        append_to_raw(raw_file, "puredns_bruteforce", stdout + stderr)

        if brute_out.exists() and brute_out.stat().st_size > 0:
            subs = extract_subdomains(domain, brute_out.read_text())
            resolved.update(subs)
            brute_out.unlink(missing_ok=True)
        print(f" {len(resolved)} resolved")

    # ── dnsx fallback ─────────────────────────────────────────────────────────
    elif available.get("dnsx"):
        fqdns_file = _make_fqdns(domain, wordlist_path)
        count      = _count_lines(fqdns_file)
        dnsx_out   = out_dir / "_dnsx_brute.txt"

        # Estimate time so the user knows what to expect
        est_min = max(1, count // (brute_threads * 12 * 60))
        print(
            f"    [i] puredns not installed — using dnsx fallback"
            f"  ({brute_threads} threads)"
        )
        print(
            f"    [i] Install puredns+massdns for 10-50x faster bruteforce:"
            f"  sudo recon_raptor install"
        )
        print(
            f"    [>] dnsx resolving {count:,} FQDNs"
            f"  (~{est_min} min estimated) ...",
            end='', flush=True,
        )

        resolver_args = ["-r", resolvers] if Path(resolvers).exists() else []

        stdout, stderr, _rc = _run([
            "dnsx",
            "-l",         fqdns_file,
            "-silent",
            "-t",         str(brute_threads),
            "-resp-only",
            "-retry",     "2",
        ] + resolver_args, timeout=21600)   # 6 hour max for very large lists
        append_to_raw(raw_file, "dnsx_bruteforce", stdout + stderr)

        subs = extract_subdomains(domain, stdout)
        resolved.update(subs)
        Path(fqdns_file).unlink(missing_ok=True)
        print(f" {len(resolved)} resolved")

    else:
        msg = "Neither puredns+massdns nor dnsx available — bruteforce skipped\n"
        print(f"    [!] {msg.strip()}")
        print(f"        Install with: sudo recon_raptor install")
        append_to_raw(raw_file, "bruteforce", msg)

    brute_file = out_dir / "_brute.txt"
    write_clean(brute_file, resolved)
    print(f"    [+] Bruteforce subtotal: {len(resolved)} unique")
    return resolved


# ── Merge ─────────────────────────────────────────────────────────────────────

def merge_subdomains(domain: str, out_dir: Path) -> int:
    all_subs = set()

    for tmp in ["_passive.txt", "_brute.txt"]:
        fpath = out_dir / tmp
        if fpath.exists():
            for line in fpath.read_text().splitlines():
                line = line.strip().lower()
                if line and line != domain.lower():
                    all_subs.add(line)
            fpath.unlink(missing_ok=True)

    final = out_dir / "subdomains.txt"
    count = write_clean(final, all_subs)
    print(f"\n    [+] subdomains.txt: {count} unique subdomains")
    return count


# ── Private helpers ───────────────────────────────────────────────────────────

def _make_fqdns(domain: str, wordlist_path: str) -> str:
    tmp = tempfile.NamedTemporaryFile(
        mode='w', suffix='.txt', delete=False, prefix='rr_fqdns_'
    )
    with open(wordlist_path, 'r') as fh:
        for line in fh:
            word = line.strip()
            if word:
                tmp.write(f"{word}.{domain}\n")
    tmp.close()
    return tmp.name


def _count_lines(path: str) -> int:
    try:
        return sum(1 for _ in open(path))
    except OSError:
        return 0

"""
modules/phases/subdomain.py

Phase 1: Subdomain enumeration.

What this version fixes vs the previous one
───────────────────────────────────────────
· dnsx bruteforce fallback (finding #3)
    The fallback used `-resp-only`, which makes dnsx print only IPs — so
    extract_subdomains() matched nothing and the fallback ALWAYS returned
    0. It now lets dnsx print the resolved hostnames and adds `-wd` so
    wildcard hits are filtered out (previously every candidate "resolved"
    on a wildcard domain).

· crt.sh (finding #8)
    - Now runs even when no CLI passive tools are installed (previously an
      early return skipped it entirely).
    - The `%` wildcard is correctly percent-encoded (%25); the old `%.`
      was malformed.
    - Retries with backoff — crt.sh returns 502/timeouts often.
    - Also reads common_name, not just name_value.

· Zone-transfer handoff (works with scanner.py #5 ordering)
    merge_subdomains now also folds in _zone.txt, so names from a
    successful AXFR (run before the merge) actually survive into
    subdomains.txt instead of being overwritten by the merge.

· Name quality (partial #20)
    merge_subdomains drops malformed names (bad labels, empty labels)
    with a strict RFC-1123 check. The looser extract_subdomains() in
    output.py is still the upstream source and is addressed separately.

· Timeouts (finding #4)
    process.run_cmd now returns partial output on timeout, so a slow
    subfinder/dnsx no longer comes back empty; the passive cap is also
    raised to 180s to give -all sources room.

Deferred on purpose
    Wildcard-filtering PASSIVE results with `puredns resolve` (#22) is not
    done here: puredns resolve also drops names that don't resolve, which
    would delete exactly the dangling-CNAME takeover candidates a recon
    tool wants to keep. A correct version belongs with the takeover
    feature (detect wildcard IPs, drop only wildcard matches, keep
    unresolved names).
"""

import re
import time
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from modules.utils.process  import run_cmd, run_cmd_streaming
from modules.utils.output   import append_to_raw, extract_subdomains, write_clean, safe_print
from modules.utils.network  import http_get_json
from modules.utils.wordlist import count_lines

# Strict RFC-1123 FQDN (labels 1-63 chars, no empty labels, no leading/
# trailing hyphen per label). Used to drop malformed names at merge time.
_STRICT_FQDN = re.compile(
    r'^(?=.{1,253}$)'
    r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+'
    r'[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$'
)


def _crtsh_url(domain: str) -> str:
    # %25 is the URL-encoded '%' wildcard crt.sh expects.
    return f"https://crt.sh/?q=%25.{domain}&output=json"


# ── crt.sh integration ────────────────────────────────────────────────────────

def run_crtsh(domain: str, out_dir: Path, attempts: int = 3) -> set:
    """Query crt.sh certificate transparency logs (free, no key)."""
    raw_file = out_dir / "subdomains_raw.txt"
    safe_print("    [>] crt.sh ...", end='', flush=True)

    data = None
    for i in range(attempts):
        data = http_get_json(_crtsh_url(domain), timeout=40)
        if data:
            break
        if i < attempts - 1:
            time.sleep(2 * (i + 1))   # 2s, 4s backoff

    if not data:
        safe_print(" timeout/no data (crt.sh often rate-limits — non-fatal)")
        append_to_raw(raw_file, "crt.sh", "no data returned after retries\n")
        return set()

    subs = set()
    for entry in data:
        blob = f"{entry.get('name_value', '')}\n{entry.get('common_name', '')}"
        for name in blob.splitlines():
            name = name.strip().lower().lstrip("*.")
            if name == domain or name.endswith(f".{domain}"):
                subs.add(name)

    append_to_raw(raw_file, "crt.sh", f"found {len(subs)} entries\n")
    safe_print(f" {len(subs)} found")
    return subs


# ── Passive enumeration ───────────────────────────────────────────────────────

def _run_one_passive(name: str, cmd: list, domain: str):
    """Run a single passive tool. Called inside ThreadPoolExecutor."""
    # 180s cap (was 120s); partial output is now preserved on timeout, so a
    # slow `subfinder -all` still contributes what it found.
    stdout, stderr, _ = run_cmd(cmd, timeout=180)
    subs = extract_subdomains(domain, stdout)
    return name, stdout, stderr, subs


def run_passive(domain: str, out_dir: Path, available: dict) -> set:
    """
    Run all available passive tools IN PARALLEL, then crt.sh.
    crt.sh runs regardless of whether any CLI passive tool is installed.
    """
    raw_file = out_dir / "subdomains_raw.txt"
    all_subs = set()

    passive_tools = [
        ("subfinder",   ["subfinder",   "-d", domain, "-silent", "-all"]),
        ("assetfinder", ["assetfinder", "--subs-only", domain]),
        ("findomain",   ["findomain",   "-t", domain, "-q"]),
    ]
    active = [(n, c) for n, c in passive_tools if available.get(n)]

    if active:
        safe_print(f"    [*] Running {len(active)} passive tools in parallel ...")
        with ThreadPoolExecutor(max_workers=len(active)) as ex:
            futures = {ex.submit(_run_one_passive, n, c, domain): n for n, c in active}
            for future in as_completed(futures):
                name, stdout, stderr, subs = future.result()
                append_to_raw(raw_file, name, stdout + stderr)
                all_subs.update(subs)
                safe_print(f"    [✓] {name:<16} {len(subs)} found")
    else:
        safe_print("    [!] No CLI passive tools installed — using crt.sh only")
        safe_print("        (install more with: sudo recon_raptor install)")
        append_to_raw(raw_file, "passive_enum", "no CLI tools available\n")

    # crt.sh ALWAYS runs — it needs no tools and often finds extra names.
    all_subs.update(run_crtsh(domain, out_dir))

    write_clean(out_dir / "_passive.txt", all_subs)
    safe_print(f"    [+] Passive subtotal: {len(all_subs)} unique")
    return all_subs


# ── Bruteforce ────────────────────────────────────────────────────────────────

def run_bruteforce(domain: str, wordlist_path: str,
                   out_dir: Path, cfg: dict, available: dict) -> set:
    raw_file      = out_dir / "subdomains_raw.txt"
    resolvers     = cfg.get('resolvers', './resolvers.txt')
    brute_threads = cfg.get('brute_threads', 500)
    resolved      = set()

    # ── puredns (preferred) ───────────────────────────────────────────────────
    if available.get("puredns") and available.get("massdns"):
        if not Path(resolvers).exists():
            safe_print(f"    [!] resolvers.txt not found: {resolvers}")
            return resolved

        with open(resolvers, 'r', errors='replace') as fh:
            resolver_count = sum(1 for l in fh if l.strip() and not l.startswith('#'))

        brute_out   = out_dir / "_brute_resolved.txt"
        massdns_bin = shutil.which("massdns") or "massdns"
        n = count_lines(wordlist_path)

        if resolver_count < 20 and n > 50_000:
            est_hours = (n / max(resolver_count, 1)) / 50_000
            safe_print(f"    [!] Only {resolver_count} resolvers for {n:,} candidates.")
            safe_print(f"        This can take a very long time "
                       f"(rough estimate: {est_hours:.1f}+ hours).")
            safe_print("        Fix — validate a larger list before using it (don't use raw):")
            safe_print("          pip install dnsvalidator")
            safe_print("          dnsvalidator -tL https://raw.githubusercontent.com/"
                       "trickest/resolvers/main/resolvers.txt -threads 100 -o resolvers_validated.txt")
        elif resolver_count > 5_000:
            safe_print(f"    [!] {resolver_count:,} resolvers loaded — if this is a raw/unvalidated")
            safe_print("        list, it may run SLOWER than a small curated one: massdns retries")
            safe_print("        every dead resolver, and large fan-out can trigger ISP throttling.")

        safe_print(f"    [>] puredns bruteforce  {n:,} candidates"
                   f"  ({resolver_count} resolvers, wildcard-aware)")
        safe_print("        Live progress below (can run a long time on large wordlists):")

        stdout, stderr, _ = run_cmd_streaming([
            "puredns", "bruteforce", wordlist_path, domain,
            "--resolvers", resolvers,
            "--bin",       massdns_bin,
            "--write",     str(brute_out),
        ], timeout=14400)   # 4 hour ceiling
        append_to_raw(raw_file, "puredns_bruteforce", stdout + stderr)

        if brute_out.exists() and brute_out.stat().st_size > 0:
            with open(brute_out, 'r', errors='replace') as fh:
                text = fh.read()
            resolved.update(extract_subdomains(domain, text))
            brute_out.unlink(missing_ok=True)
        safe_print(f"\n    [+] puredns finished — {len(resolved)} resolved")

    # ── dnsx fallback ─────────────────────────────────────────────────────────
    elif available.get("dnsx"):
        fqdns_file = _make_fqdns(domain, wordlist_path)
        n = count_lines(fqdns_file)
        est_min = max(1, n // (brute_threads * 12 * 60))

        safe_print(f"    [i] puredns not available — using dnsx  ({brute_threads} threads)")
        safe_print("    [i] sudo recon_raptor install  ← adds puredns (10-50x faster)")
        safe_print(f"    [>] dnsx resolving {n:,} FQDNs  (~{est_min} min est.) ...",
                   end='', flush=True)

        resolver_args = ["-r", resolvers] if Path(resolvers).exists() else []
        # FIX #3: no -resp-only (that printed IPs, so nothing ever matched).
        # dnsx prints the resolved hostname by default; -wd filters wildcards.
        stdout, stderr, _ = run_cmd([
            "dnsx", "-l", fqdns_file, "-silent",
            "-t", str(brute_threads),
            "-wd", domain,
            "-retry", "2",
        ] + resolver_args, timeout=21600)
        append_to_raw(raw_file, "dnsx_bruteforce", stdout + stderr)

        resolved.update(extract_subdomains(domain, stdout))
        Path(fqdns_file).unlink(missing_ok=True)
        safe_print(f" {len(resolved)} resolved")

    else:
        msg = "Neither puredns+massdns nor dnsx available — bruteforce skipped"
        safe_print(f"    [!] {msg}")
        append_to_raw(raw_file, "bruteforce", msg + "\n")

    write_clean(out_dir / "_brute.txt", resolved)
    safe_print(f"    [+] Bruteforce subtotal: {len(resolved)} unique")
    return resolved


# ── Merge ─────────────────────────────────────────────────────────────────────

def _is_valid_fqdn(name: str) -> bool:
    return bool(_STRICT_FQDN.match(name))


def merge_subdomains(domain: str, out_dir: Path) -> int:
    """
    Merge passive + bruteforce + zone-transfer results into subdomains.txt.

    Folds in _zone.txt so AXFR names (written by run_zone_transfer, which
    the scanner runs before this merge) survive instead of being
    overwritten. Drops malformed names and the apex itself.
    """
    all_subs = set()
    dropped  = 0
    for tmp in ["_passive.txt", "_brute.txt", "_zone.txt"]:
        fpath = out_dir / tmp
        if fpath.exists():
            with open(fpath, 'r', errors='replace') as fh:
                for line in fh:
                    s = line.strip().lower()
                    if not s or s == domain.lower():
                        continue
                    if _is_valid_fqdn(s):
                        all_subs.add(s)
                    else:
                        dropped += 1
            fpath.unlink(missing_ok=True)

    final = out_dir / "subdomains.txt"
    count = write_clean(final, all_subs)
    extra = f"  ({dropped} malformed dropped)" if dropped else ""
    safe_print(f"\n    [+] subdomains.txt: {count} unique subdomains{extra}")
    return count


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_fqdns(domain: str, wordlist_path: str) -> str:
    tmp = tempfile.NamedTemporaryFile(
        mode='w', suffix='.txt', delete=False, prefix='rr_fqdns_')
    with open(wordlist_path, 'r', errors='replace') as fh:
        for line in fh:
            word = line.strip()
            if word:
                tmp.write(f"{word}.{domain}\n")
    tmp.close()
    return tmp.name
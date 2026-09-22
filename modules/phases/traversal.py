"""
modules/phases/traversal.py

Phase 6: Directory traversal.

What this version fixes vs the previous one
───────────────────────────────────────────
· One primary tool by default (finding #42)
    Running gobuster + dirsearch + ffuf all with the same wordlist on every
    host did ~3x the work for near-identical results. By default this now
    runs a single primary tool (ffuf → gobuster → dirsearch, whichever is
    available first). Set `traversal_all_tools: true` in config.yaml to keep
    the old run-everything behaviour.

· ffuf auto-calibration (finding #17)
    ffuf runs with -ac so soft-404 / catch-all servers don't report every
    word as a hit.

· dirsearch JSON parsing (finding #16)
    Current dirsearch versions write full URLs in plain format, so the old
    "find a token starting with /" parser silently found nothing. This uses
    --format json and parses it.

· Case-sensitive path dedup (finding #19)
    Deduplication now lowercases only scheme+host, never the path, so /Admin
    and /admin are kept as distinct results (paths are case-sensitive on most
    servers). This replaces output.write_traversal()'s whole-line lowercase
    key for this phase.

· Rate limiting + no leading-slash double joins (findings #43, #18)
    ffuf gets -rate; base URLs are stripped of trailing slashes so
    {url}/FUZZ never becomes host//word. (harvest now emits bare paths too.)

· The gobuster --depth capability probe is cached once instead of spawned
  per host (finding #44, minor).
"""

import json
import re
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from modules.utils.process import run_cmd
from modules.utils.output  import append_to_raw, safe_print

_MAX_EXTENSIONS = 8   # cap to avoid ext-count × wordlist request blow-up
_gobuster_depth_cache = None


def _url_from_alive_line(line: str):
    token = line.strip().split()[0] if line.strip() else ""
    return token.rstrip('/') if token.startswith("http") else None


def _safe_slug(url: str) -> str:
    return re.sub(r'[^\w]', '_', url)[:80]


def _dedup_key(line: str) -> str:
    """
    Dedup key that preserves path case. Lowercases scheme+host only.
    'https://X.com/Admin [200]' and '.../admin [404]' stay distinct.
    """
    token = line.strip().split()[0] if line.strip() else ""
    m = re.match(r'^(https?://[^/]+)(/.*)?$', token)
    if m:
        return m.group(1).lower() + (m.group(2) or '').rstrip('/')
    return token.rstrip('/')


def _write_paths(filepath: Path, lines: list) -> int:
    """Write URL-deduplicated results, case-sensitive on the path."""
    seen, unique = set(), []
    for line in sorted(lines, key=_dedup_key):
        line = line.strip()
        if not line:
            continue
        k = _dedup_key(line)
        if k and k not in seen:
            seen.add(k)
            unique.append(line)
    filepath.write_text('\n'.join(unique) + ('\n' if unique else ''))
    return len(unique)


def _extensions(cfg: dict) -> list:
    exts = cfg.get('extensions', ['php', 'html', 'txt'])
    if len(exts) > _MAX_EXTENSIONS:
        safe_print(f"    [i] {len(exts)} extensions configured — using first "
                   f"{_MAX_EXTENSIONS} to keep request volume sane "
                   f"(each extension multiplies requests per word)")
        exts = exts[:_MAX_EXTENSIONS]
    return exts


def _gobuster_supports_depth() -> bool:
    global _gobuster_depth_cache
    if _gobuster_depth_cache is None:
        stdout, stderr, _ = run_cmd(["gobuster", "dir", "--help"], timeout=5)
        _gobuster_depth_cache = "--depth" in (stdout + stderr)
    return _gobuster_depth_cache


# ── Tool wrappers ─────────────────────────────────────────────────────────────

def _ffuf(url: str, wordlist: str, out_file: Path, cfg: dict, raw_file: Path) -> list:
    threads = cfg.get('threads', 50)
    timeout = cfg.get('timeout', 10)
    rate    = cfg.get('rate', 150)
    exts    = ','.join('.' + e for e in _extensions(cfg))

    cmd = [
        "ffuf",
        "-u",       f"{url.rstrip('/')}/FUZZ",
        "-w",       wordlist,
        "-t",       str(threads),
        "-timeout", str(timeout),
        "-rate",    str(rate),
        "-e",       exts,
        "-ac",                       # auto-calibrate — kills soft-404 noise
        "-mc",      "200,201,204,301,302,307,401,403,405",
        "-of",      "json",
        "-o",       str(out_file),
        "-s",
    ]
    stdout, stderr, _ = run_cmd(cmd, timeout=3600)
    append_to_raw(raw_file, f"ffuf:{url}", stdout + stderr)

    paths = []
    if out_file.exists():
        try:
            with open(out_file, 'r', errors='replace') as fh:
                data = json.load(fh)
            for result in data.get('results', []):
                found_url = result.get('url', '')
                status    = result.get('status', '')
                length    = result.get('length', '')
                if found_url:
                    paths.append(f"{found_url}  [Status: {status}, Size: {length}]")
        except (json.JSONDecodeError, KeyError, OSError):
            pass
    return paths


def _gobuster(url: str, wordlist: str, out_file: Path, cfg: dict, raw_file: Path) -> list:
    threads = cfg.get('threads', 50)
    timeout = cfg.get('timeout', 10)
    exts    = ','.join(_extensions(cfg))
    depth   = cfg.get('depth', 2)

    cmd = [
        "gobuster", "dir",
        "-u",        url.rstrip('/'),
        "-w",        wordlist,
        "-t",        str(threads),
        "--timeout", f"{timeout}s",
        "-x",        exts,
        "-q", "--no-error",
        "-o",        str(out_file),
    ]
    if _gobuster_supports_depth():
        cmd += ["--depth", str(depth)]

    stdout, stderr, _ = run_cmd(cmd, timeout=3600)
    append_to_raw(raw_file, f"gobuster:{url}", stdout + stderr)

    paths = []
    if out_file.exists():
        with open(out_file, 'r', errors='replace') as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith('#') and '(Status:' in line:
                    path     = line.split()[0]
                    status_m = re.search(r'Status:\s*(\d+)', line)
                    size_m   = re.search(r'Size:\s*(\d+)',   line)
                    status   = status_m.group(1) if status_m else ""
                    size     = size_m.group(1)   if size_m   else ""
                    paths.append(f"{url.rstrip('/')}{path}  [Status: {status}, Size: {size}]")
    return paths


def _dirsearch(url: str, wordlist: str, out_file: Path, cfg: dict, raw_file: Path) -> list:
    threads = cfg.get('threads', 50)
    exts    = ','.join(_extensions(cfg))
    depth   = cfg.get('depth', 2)

    cmd = [
        "dirsearch",
        "-u",                url.rstrip('/'),
        "-w",                wordlist,
        "-t",                str(threads),
        "-e",                exts,
        "--recursion-depth", str(depth),
        "--format",          "json",     # FIX #16: was "plain" → unparseable
        "-o",                str(out_file),
        "--quiet",
    ]
    stdout, stderr, _ = run_cmd(cmd, timeout=3600)
    append_to_raw(raw_file, f"dirsearch:{url}", stdout + stderr)

    return _parse_dirsearch_json(out_file)


def _parse_dirsearch_json(out_file: Path) -> list:
    paths = []
    if not out_file.exists():
        return paths
    try:
        with open(out_file, 'r', errors='replace') as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return paths

    # dirsearch json: {"results": [{"url":..., "status":..., "content-length":...}]}
    # (older builds nest per-target; handle both dict-of-lists and flat list).
    results = []
    if isinstance(data, dict):
        if isinstance(data.get('results'), list):
            results = data['results']
        else:
            for v in data.values():
                if isinstance(v, list):
                    results.extend(v)
    elif isinstance(data, list):
        results = data

    for entry in results:
        if not isinstance(entry, dict):
            continue
        found_url = entry.get('url') or entry.get('path') or ''
        status    = entry.get('status') or entry.get('status-code') or ''
        length    = (entry.get('content-length') or entry.get('length')
                     or entry.get('size') or '')
        if found_url:
            paths.append(f"{found_url}  [Status: {status}, Size: {length}]")
    return paths


# ── Tool selection ────────────────────────────────────────────────────────────

_TOOL_FNS = {"ffuf": _ffuf, "gobuster": _gobuster, "dirsearch": _dirsearch}
_PRIMARY_ORDER = ["ffuf", "gobuster", "dirsearch"]


def _choose_tools(cfg: dict, available: dict) -> list:
    have = [t for t in _PRIMARY_ORDER if available.get(t)]
    if not have:
        return []
    if cfg.get('traversal_all_tools', False):
        return have
    return [have[0]]   # single primary tool


# ── Per-host runner ───────────────────────────────────────────────────────────

def _scan_one_host(url: str, wordlist: str, tmp_dir: Path,
                   cfg: dict, raw_file: Path, tools: list) -> list:
    paths = []
    slug  = _safe_slug(url)
    for tool in tools:
        ext = "json" if tool in ("ffuf", "dirsearch") else "txt"
        out = tmp_dir / f"{tool}_{slug}.{ext}"
        p   = _TOOL_FNS[tool](url, wordlist, out, cfg, raw_file)
        safe_print(f"        {tool:<10} {url}  →  {len(p)} paths")
        paths.extend(p)
    return paths


# ── Main entrypoint ───────────────────────────────────────────────────────────

def run_traversal(domain: str, alive_file: Path, dir_wordlist: str,
                  out_dir: Path, cfg: dict, available: dict):
    raw_file  = out_dir / "traversal_raw.txt"
    final_out = out_dir / "traversal.txt"
    tmp_dir   = out_dir / "_traversal_tmp"

    if not dir_wordlist:
        safe_print("    [!] No directory traversal wordlist — skipped")
        safe_print("        Set dir_wordlist in config.yaml or use -dw flag")
        return

    tools = _choose_tools(cfg, available)
    if not tools:
        safe_print("    [!] No traversal tools available (gobuster/dirsearch/ffuf)")
        safe_print("        Install: sudo recon_raptor install")
        return

    with open(alive_file, 'r', errors='replace') as fh:
        alive_lines = [l.strip() for l in fh if l.strip()]
    urls = [u for u in (_url_from_alive_line(l) for l in alive_lines) if u]
    # De-dup identical URLs (httpx can list http+https variants of one host).
    urls = sorted(set(urls))

    if not urls:
        safe_print("    [i] No alive hosts — traversal skipped")
        return

    tmp_dir.mkdir(exist_ok=True)
    all_paths = []

    mode = "all tools" if len(tools) > 1 else f"primary: {tools[0]}"
    safe_print(f"    [*] Tools: {', '.join(tools)}  ({mode})")
    safe_print(f"    [*] Targets: {len(urls)} alive hosts (parallel)")

    max_workers = min(len(urls), cfg.get('traversal_jobs', 3))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_scan_one_host, url, dir_wordlist, tmp_dir,
                      cfg, raw_file, tools): url
            for url in urls
        }
        for future in as_completed(futures):
            url = futures[future]
            try:
                paths = future.result()
                all_paths.extend(paths)
                safe_print(f"    [✓] {url}  total: {len(paths)} paths")
            except Exception as exc:
                safe_print(f"    [!] {url}  error: {exc}")

    count = _write_paths(final_out, all_paths)
    safe_print(f"\n    [+] traversal.txt: {count} unique paths (case-sensitive)")

    shutil.rmtree(tmp_dir, ignore_errors=True)
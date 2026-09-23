"""
modules/phases/traversal.py

Phase 6: Directory traversal.

What this version does (and why)
────────────────────────────────
A directory wordlist mixes two kinds of entry:
  · directory words  — bare names used as path segments: admin, info, contacts
  · file entries     — names with an extension or dotfiles: debug.log, .env, config.php

These need different handling:
  · Directory words seed the directory tree AND get the configured extensions
    appended (admin → admin, admin.php, admin.bak). They are what recursion
    descends into.
  · File entries are probed literally — extensions are NOT appended to them
    (so 'debug.log' never becomes the nonsense 'debug.log.php').

Recursion is enabled, so once a directory word resolves to a real directory,
the SAME effective wordlist — including every file entry — is fuzzed inside it,
and inside directories found there, up to the configured depth. That yields:

    example.com/debug.log
    example.com/info/debug.log
    example.com/info/contacts/debug.log

from a wordlist containing just {info, contacts, debug.log}.

Extensions are baked into the effective wordlist once, up front, so the tools
are NOT given their own -e/-x flag (which would double-append and reintroduce
the debug.log.php problem).

Other properties
────────────────
· One primary tool by default (ffuf → dirsearch → gobuster); set
  `traversal_all_tools: true` to run all available. ffuf and dirsearch support
  recursion; gobuster's `dir` mode does not, so under gobuster only the root
  level is fuzzed (a note is printed).
· ffuf runs with -ac (soft-404 auto-calibration) and -rate (rate limiting).
· Results are deduplicated case-sensitively on the path.
"""

import json
import re
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from modules.utils.process import run_cmd
from modules.utils.output  import append_to_raw, safe_print

_MAX_EXTENSIONS = 8
_gobuster_depth_cache = None

# A trailing-segment with a 1–7 char alphanumeric extension → treat as a file.
_EXT_RE = re.compile(r'^.+\.[A-Za-z0-9]{1,7}$')


# ── Wordlist classification ───────────────────────────────────────────────────

def _is_file_entry(word: str) -> bool:
    """True if the entry names a file (has an extension or is a dotfile)."""
    seg = word.rstrip('/').rsplit('/', 1)[-1]
    if not seg:
        return False
    if seg.startswith('.'):          # .env, .htaccess, .git/... → file-like
        return True
    return bool(_EXT_RE.match(seg))


def _extensions(cfg: dict) -> list:
    exts = cfg.get('extensions', ['php', 'html', 'txt'])
    if len(exts) > _MAX_EXTENSIONS:
        safe_print(f"    [i] {len(exts)} extensions configured — using first "
                   f"{_MAX_EXTENSIONS} to keep request volume sane")
        exts = exts[:_MAX_EXTENSIONS]
    return [e.lstrip('.') for e in exts]


def _build_effective_wordlist(src_wordlist: str, extensions: list,
                              tmp_dir: Path):
    """
    Build the effective wordlist:
      dir words        (as-is)
      dir words × ext  (admin.php, admin.bak, …)
      file entries     (as-is, no extension appended)

    Recursion (enabled in the tool calls) is what probes file entries INSIDE
    discovered directories — we don't pre-join them here.

    Returns (path, n_dir_words, n_file_entries, n_total).
    """
    dir_words, file_entries, seen = [], [], set()
    with open(src_wordlist, 'r', errors='replace') as fh:
        for line in fh:
            w = line.strip().lstrip('/')
            if not w or w in seen:
                continue
            seen.add(w)
            (file_entries if _is_file_entry(w) else dir_words).append(w)

    entries, added = [], set()

    def _push(x):
        if x and x not in added:
            added.add(x)
            entries.append(x)

    for w in dir_words:
        _push(w)
        for e in extensions:
            _push(f"{w}.{e}")
    for f in file_entries:
        _push(f)

    out = tmp_dir / "_effective_wordlist.txt"
    out.write_text('\n'.join(entries) + ('\n' if entries else ''))
    return str(out), len(dir_words), len(file_entries), len(entries)


# ── Result helpers ────────────────────────────────────────────────────────────

def _url_from_alive_line(line: str):
    token = line.strip().split()[0] if line.strip() else ""
    return token.rstrip('/') if token.startswith("http") else None


def _safe_slug(url: str) -> str:
    return re.sub(r'[^\w]', '_', url)[:80]


def _dedup_key(line: str) -> str:
    token = line.strip().split()[0] if line.strip() else ""
    m = re.match(r'^(https?://[^/]+)(/.*)?$', token)
    if m:
        return m.group(1).lower() + (m.group(2) or '').rstrip('/')
    return token.rstrip('/')


def _write_paths(filepath: Path, lines: list) -> int:
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


def _gobuster_supports_depth() -> bool:
    global _gobuster_depth_cache
    if _gobuster_depth_cache is None:
        stdout, stderr, _ = run_cmd(["gobuster", "dir", "--help"], timeout=5)
        _gobuster_depth_cache = "--depth" in (stdout + stderr)
    return _gobuster_depth_cache


# ── Tool wrappers (extensions already baked into the wordlist) ────────────────

def _ffuf(url: str, wordlist: str, out_file: Path, cfg: dict, raw_file: Path) -> list:
    threads = cfg.get('threads', 50)
    timeout = cfg.get('timeout', 10)
    rate    = cfg.get('rate', 150)
    depth   = cfg.get('depth', 2)

    cmd = [
        "ffuf",
        "-u",       f"{url.rstrip('/')}/FUZZ",
        "-w",       wordlist,
        "-t",       str(threads),
        "-timeout", str(timeout),
        "-rate",    str(rate),
        "-ac",                                  # soft-404 auto-calibration
        "-recursion",                           # descend into found directories
        "-recursion-depth", str(depth),
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


def _dirsearch(url: str, wordlist: str, out_file: Path, cfg: dict, raw_file: Path) -> list:
    threads = cfg.get('threads', 50)
    depth   = cfg.get('depth', 2)

    cmd = [
        "dirsearch",
        "-u",                url.rstrip('/'),
        "-w",                wordlist,
        "-t",                str(threads),
        "-r",                             # recursive
        "--recursion-depth", str(depth),
        "--format",          "json",
        "-o",                str(out_file),
        "--quiet",
    ]
    stdout, stderr, _ = run_cmd(cmd, timeout=3600)
    append_to_raw(raw_file, f"dirsearch:{url}", stdout + stderr)
    return _parse_dirsearch_json(out_file)


def _gobuster(url: str, wordlist: str, out_file: Path, cfg: dict, raw_file: Path) -> list:
    threads = cfg.get('threads', 50)
    timeout = cfg.get('timeout', 10)

    # gobuster `dir` has no recursion — root level only. Extensions are already
    # in the wordlist, so no -x flag here.
    cmd = [
        "gobuster", "dir",
        "-u",        url.rstrip('/'),
        "-w",        wordlist,
        "-t",        str(threads),
        "--timeout", f"{timeout}s",
        "-q", "--no-error",
        "-o",        str(out_file),
    ]
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


def _parse_dirsearch_json(out_file: Path) -> list:
    paths = []
    if not out_file.exists():
        return paths
    try:
        with open(out_file, 'r', errors='replace') as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return paths

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

_TOOL_FNS = {"ffuf": _ffuf, "dirsearch": _dirsearch, "gobuster": _gobuster}
# ffuf/dirsearch first because they support the recursion this phase relies on.
_PRIMARY_ORDER = ["ffuf", "dirsearch", "gobuster"]


def _choose_tools(cfg: dict, available: dict) -> list:
    have = [t for t in _PRIMARY_ORDER if available.get(t)]
    if not have:
        return []
    if cfg.get('traversal_all_tools', False):
        return have
    return [have[0]]


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
        safe_print("    [!] No traversal tools available (ffuf/dirsearch/gobuster)")
        safe_print("        Install: sudo recon_raptor install")
        return

    with open(alive_file, 'r', errors='replace') as fh:
        alive_lines = [l.strip() for l in fh if l.strip()]
    urls = sorted({u for u in (_url_from_alive_line(l) for l in alive_lines) if u})
    if not urls:
        safe_print("    [i] No alive hosts — traversal skipped")
        return

    tmp_dir.mkdir(exist_ok=True)

    # Split + expand the wordlist once, shared across all hosts.
    eff_wl, n_dirs, n_files, n_total = _build_effective_wordlist(
        dir_wordlist, _extensions(cfg), tmp_dir)
    safe_print(f"    [*] Wordlist: {n_dirs} directory words, {n_files} file entries "
               f"→ {n_total:,} effective entries (extensions on dir words only)")

    if "gobuster" in tools and not any(t in tools for t in ("ffuf", "dirsearch")):
        safe_print("    [i] gobuster has no recursion — files-inside-directories "
                   "won't be found. Install ffuf or dirsearch for that.")

    mode = "all tools" if len(tools) > 1 else f"primary: {tools[0]}"
    safe_print(f"    [*] Tools: {', '.join(tools)}  ({mode})  "
               f"recursion depth {cfg.get('depth', 2)}")
    safe_print(f"    [*] Targets: {len(urls)} alive hosts (parallel)")

    all_paths = []
    max_workers = min(len(urls), cfg.get('traversal_jobs', 3))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(_scan_one_host, url, eff_wl, tmp_dir, cfg, raw_file, tools): url
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
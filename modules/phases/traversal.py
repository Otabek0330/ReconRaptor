"""
modules/phases/traversal.py

Phase 4: Directory traversal.

Runs available tools against every URL in alive.txt:
  · gobuster dir  — fast, reliable, good for large wordlists
  · dirsearch     — recursive, extension-aware
  · ffuf          — flexible fuzzer with JSON output

Results from all tools on all hosts are merged and deduplicated into
traversal.txt.  Raw outputs go to traversal_raw.txt.
"""

import subprocess
import json
import shutil
from pathlib import Path

from modules.utils.output import append_to_raw, write_clean


def _run(cmd, timeout=600):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "[timeout]", -1
    except FileNotFoundError:
        return "", f"[{cmd[0]} not found]", -1
    except Exception as e:
        return "", str(e), -1


def _url_from_alive_line(line: str) -> str | None:
    """Extract the URL (first token) from an alive.txt line."""
    token = line.strip().split()[0] if line.strip() else ""
    return token if token.startswith("http") else None


def _safe_slug(url: str) -> str:
    """Convert a URL to a filesystem-safe name for temp files."""
    return url.replace("://", "_").replace("/", "_").replace(":", "_")[:80]


# ── Tool wrappers ─────────────────────────────────────────────────────────────

def _gobuster(url: str, wordlist: str, out_file: Path,
              cfg: dict, raw_file: Path) -> list[str]:
    threads    = cfg.get('threads', 50)
    timeout    = cfg.get('timeout', 10)
    extensions = ','.join(cfg.get('extensions', ['php', 'html', 'txt']))
    depth      = cfg.get('depth', 2)

    cmd = [
        "gobuster", "dir",
        "-u",       url,
        "-w",       wordlist,
        "-t",       str(threads),
        "--timeout", f"{timeout}s",
        "-x",       extensions,
        "--depth",  str(depth),
        "-q",
        "--no-error",
        "-o",       str(out_file),
    ]
    stdout, stderr, _rc = _run(cmd, timeout=1800)
    append_to_raw(raw_file, f"gobuster:{url}", stdout + stderr)

    paths = []
    if out_file.exists():
        for line in out_file.read_text(errors='replace').splitlines():
            line = line.strip()
            # gobuster output: "/path   (Status: 200) [Size: 1234]"
            if line and not line.startswith('#') and '(Status:' in line:
                paths.append(f"{url}{line.split()[0]}")
    return paths


def _dirsearch(url: str, wordlist: str, out_file: Path,
               cfg: dict, raw_file: Path) -> list[str]:
    threads    = cfg.get('threads', 50)
    extensions = ','.join(cfg.get('extensions', ['php', 'html', 'txt']))
    depth      = cfg.get('depth', 2)

    cmd = [
        "dirsearch",
        "-u",                 url,
        "-w",                 wordlist,
        "-t",                 str(threads),
        "-e",                 extensions,
        "--recursion-depth",  str(depth),
        "--format",           "plain",
        "-o",                 str(out_file),
        "--quiet",
    ]
    stdout, stderr, _rc = _run(cmd, timeout=1800)
    append_to_raw(raw_file, f"dirsearch:{url}", stdout + stderr)

    paths = []
    if out_file.exists():
        for line in out_file.read_text(errors='replace').splitlines():
            line = line.strip()
            if line and not line.startswith('#') and line.startswith('/'):
                paths.append(f"{url}{line.split()[0]}")
    return paths


def _ffuf(url: str, wordlist: str, out_file: Path,
          cfg: dict, raw_file: Path) -> list[str]:
    threads    = cfg.get('threads', 50)
    timeout    = cfg.get('timeout', 10)
    rate       = cfg.get('rate', 150)
    extensions = ','.join('.' + e for e in cfg.get('extensions', ['php', 'html', 'txt']))

    cmd = [
        "ffuf",
        "-u",        f"{url}/FUZZ",
        "-w",        wordlist,
        "-t",        str(threads),
        "-timeout",  str(timeout),
        "-rate",     str(rate),
        "-e",        extensions,
        "-mc",       "200,201,204,301,302,307,401,403,405",
        "-of",       "json",
        "-o",        str(out_file),
        "-s",        # silent
    ]
    stdout, stderr, _rc = _run(cmd, timeout=1800)
    append_to_raw(raw_file, f"ffuf:{url}", stdout + stderr)

    paths = []
    if out_file.exists():
        try:
            data = json.loads(out_file.read_text())
            for result in data.get('results', []):
                found_url = result.get('url', '')
                status    = result.get('status', '')
                length    = result.get('length', '')
                if found_url:
                    paths.append(f"{found_url}  [Status: {status}, Size: {length}]")
        except (json.JSONDecodeError, KeyError):
            pass
    return paths


# ── Main entrypoint ───────────────────────────────────────────────────────────

def run_traversal(domain: str, alive_file: Path, wordlist_path: str | None,
                  out_dir: Path, cfg: dict, available: dict):
    """
    Run directory traversal against every live host in alive_file.
    """
    raw_file  = out_dir / "traversal_raw.txt"
    final_out = out_dir / "traversal.txt"
    tmp_dir   = out_dir / "_traversal_tmp"

    if not wordlist_path:
        print("    [!] No wordlist available — traversal skipped")
        return

    has_gobuster  = bool(available.get("gobuster"))
    has_dirsearch = bool(available.get("dirsearch"))
    has_ffuf      = bool(available.get("ffuf"))

    if not any([has_gobuster, has_dirsearch, has_ffuf]):
        print("    [!] No traversal tools available (gobuster / dirsearch / ffuf)")
        print("        Install them: sudo recon_raptor install")
        return

    alive_lines = [
        l.strip() for l in alive_file.read_text(errors='replace').splitlines()
        if l.strip()
    ]
    if not alive_lines:
        print("    [i] No alive hosts — traversal skipped")
        return

    tmp_dir.mkdir(exist_ok=True)
    all_paths = set()

    running = []
    if has_gobuster:  running.append("gobuster")
    if has_dirsearch: running.append("dirsearch")
    if has_ffuf:      running.append("ffuf")
    print(f"    [*] Tools: {', '.join(running)}")
    print(f"    [*] Targets: {len(alive_lines)} alive hosts\n")

    for i, alive_line in enumerate(alive_lines, 1):
        url = _url_from_alive_line(alive_line)
        if not url:
            continue

        slug = _safe_slug(url)
        print(f"    [{i}/{len(alive_lines)}] {url}")

        if has_gobuster:
            out = tmp_dir / f"gobuster_{slug}.txt"
            paths = _gobuster(url, wordlist_path, out, cfg, raw_file)
            all_paths.update(paths)
            print(f"        gobuster:  {len(paths)} paths")

        if has_dirsearch:
            out = tmp_dir / f"dirsearch_{slug}.txt"
            paths = _dirsearch(url, wordlist_path, out, cfg, raw_file)
            all_paths.update(paths)
            print(f"        dirsearch: {len(paths)} paths")

        if has_ffuf:
            out = tmp_dir / f"ffuf_{slug}.json"
            paths = _ffuf(url, wordlist_path, out, cfg, raw_file)
            all_paths.update(paths)
            print(f"        ffuf:      {len(paths)} paths")

    count = write_clean(final_out, all_paths)
    print(f"\n    [+] traversal.txt: {count} unique paths across all hosts")

    shutil.rmtree(tmp_dir, ignore_errors=True)

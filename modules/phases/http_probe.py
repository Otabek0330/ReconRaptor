"""
modules/phases/http_probe.py

Phase 3: HTTP probing.

Runs httpx against the full subdomain list to find live HTTP/HTTPS services.
Probes ports listed in config.ports (default: 80, 443, 8080, 8443).

Fixes vs v1:
  · Handles both old httpx JSON field names (status-code, tech) and
    new ones (status_code, technologies) — newer httpx changed these.
  · Falls back to plain-text output parsing if JSON parse fails.
  · Prints a raw sample line when no results found to aid debugging.

Output:
  alive.txt — one line per live host:
              URL  [STATUS]  "Page title"  [tech1, tech2]
"""

import subprocess
import json
from pathlib import Path

from modules.utils.output import append_to_raw, write_clean


def _run(cmd, timeout=900):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "[timeout]", -1
    except FileNotFoundError:
        return "", f"[{cmd[0]} not found]", -1
    except Exception as e:
        return "", str(e), -1


def _parse_httpx_line(line: str) -> str | None:
    """
    Parse one httpx output line — tries JSON first, falls back to plain text.
    Returns a formatted alive-line or None.

    httpx JSON field names changed across versions:
      status-code  (<=1.2.x)  →  status_code  (>=1.3.x)
      tech         (<=1.2.x)  →  technologies (>=1.3.x)
    We handle both.
    """
    line = line.strip()
    if not line:
        return None

    # ── JSON path ─────────────────────────────────────────────────────────────
    if line.startswith('{'):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return None

        url = entry.get("url", "")
        if not url:
            return None

        # Status code — handle both naming conventions
        status = (
            entry.get("status_code") or
            entry.get("status-code") or
            ""
        )

        # Title
        title = str(entry.get("title", "") or "").replace('"', "'").strip()

        # Technologies — handle both naming conventions
        techs = (
            entry.get("technologies") or
            entry.get("tech") or
            []
        )
        if isinstance(techs, str):
            techs = [techs]

        parts = [url, f"[{status}]"]
        if title:
            parts.append(f'"{title}"')
        if techs:
            parts.append(f"[{', '.join(str(t) for t in techs)}]")

        return "  ".join(parts)

    # ── Plain-text path ───────────────────────────────────────────────────────
    # httpx without -json outputs: "https://example.com [200]"
    if line.startswith("http"):
        return line

    return None


def run_http_probe(domain: str, subs_file: Path,
                   out_dir: Path, cfg: dict, available: dict):
    """
    Probe all subdomains for live web services with httpx.
    """
    raw_file   = out_dir / "subdomains_raw.txt"
    alive_file = out_dir / "alive.txt"

    if not available.get("httpx"):
        msg = "httpx not installed — HTTP probe skipped\n"
        print(f"    [!] {msg.strip()}")
        append_to_raw(raw_file, "httpx", msg)
        return

    threads   = cfg.get('threads', 50)
    timeout   = cfg.get('timeout', 10)
    ports     = cfg.get('ports', [80, 443, 8080, 8443])
    ports_str = ','.join(str(p) for p in ports)

    sub_count = sum(1 for _ in open(subs_file))
    print(f"    [>] httpx  {sub_count:,} hosts  ports [{ports_str}] ...", end='', flush=True)

    stdout, stderr, _rc = _run([
        "httpx",
        "-l",               str(subs_file),
        "-silent",
        "-threads",         str(threads),
        "-timeout",         str(timeout),
        "-ports",           ports_str,
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-json",
    ], timeout=1200)

    append_to_raw(raw_file, "httpx", stdout + stderr)

    # ── Parse output ──────────────────────────────────────────────────────────
    alive_lines = []
    for line in stdout.splitlines():
        parsed = _parse_httpx_line(line)
        if parsed:
            alive_lines.append(parsed)

    # Debug: if nothing found, show what httpx actually said
    if not alive_lines and stdout.strip():
        sample = stdout.strip().splitlines()[:3]
        print(f"\n    [!] httpx produced output but parsing found 0 results.")
        print(f"        Sample output (first 3 lines):")
        for s in sample:
            print(f"          {s[:120]}")
        # Retry without JSON — plain text output always works
        print(f"    [>] Retrying httpx without JSON mode ...", end='', flush=True)
        stdout2, stderr2, _ = _run([
            "httpx",
            "-l",        str(subs_file),
            "-silent",
            "-threads",  str(threads),
            "-timeout",  str(timeout),
            "-ports",    ports_str,
            "-sc",       # short flag for status code
        ], timeout=1200)
        append_to_raw(raw_file, "httpx_plaintext_retry", stdout2 + stderr2)
        for line in stdout2.splitlines():
            parsed = _parse_httpx_line(line)
            if parsed:
                alive_lines.append(parsed)

    count = write_clean(alive_file, alive_lines)
    print(f" {count} alive")
    if count > 0:
        print(f"    [+] alive.txt: {count} live hosts")
    else:
        print(f"    [i] No live HTTP/HTTPS hosts found on the probed ports")
        print(f"        Raw httpx output saved to: subdomains_raw.txt")

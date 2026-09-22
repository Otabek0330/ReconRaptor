"""
modules/utils/output.py

Helpers for:
  · Thread-safe console output (traversal + enrichment run in parallel)
  · Creating per-domain output directories
  · Writing clean (sorted, deduped) result files
  · write_traversal() — URL-only dedup (legacy; traversal.py now dedups itself)
  · Appending raw tool output to the raw log
  · Extracting subdomain candidates from arbitrary tool output
  · Printing phase/domain headers to stdout

What this version fixes vs the previous one
───────────────────────────────────────────
· extract_subdomains is strict and URL-aware (finding #20)
    The old version accepted malformed names (e.g. '-x.example.com',
    'a..example.com') and missed hostnames embedded in URLs. It now pulls
    the host out of URL tokens, strips ports, and validates each name as a
    proper RFC-1123 FQDN before keeping it.
"""

import re
import threading
from datetime import datetime
from pathlib import Path

# ── Thread-safe console ───────────────────────────────────────────────────────
_stdout_lock = threading.Lock()

# Strict RFC-1123 FQDN (no empty labels, no leading/trailing hyphen per label).
_STRICT_FQDN = re.compile(
    r'^(?=.{1,253}$)'
    r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+'
    r'[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$'
)


def safe_print(*args, **kwargs):
    """Thread-safe drop-in for print() — used by all phase modules."""
    with _stdout_lock:
        print(*args, **kwargs)


# ── Directory setup ───────────────────────────────────────────────────────────

def setup_domain_dir(domain: str, results_root) -> Path:
    out_dir = Path(results_root) / domain
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


# ── Generic file writer ───────────────────────────────────────────────────────

def write_clean(filepath, lines) -> int:
    """Write sorted, deduplicated non-empty lines. Returns count."""
    filepath = Path(filepath)
    unique   = sorted({str(l).strip() for l in lines if str(l).strip()})
    filepath.write_text('\n'.join(unique) + ('\n' if unique else ''))
    return len(unique)


# ── Traversal-specific writer (legacy) ────────────────────────────────────────

def _url_key(line: str) -> str:
    token = line.strip().split()[0] if line.strip() else ""
    return token.rstrip('/').lower()


def write_traversal(filepath, lines) -> int:
    """
    Write traversal results deduplicating by URL only.
    NOTE: traversal.py now does its own case-sensitive dedup; this remains
    for backward compatibility with any other caller.
    """
    filepath  = Path(filepath)
    seen_urls = set()
    unique    = []
    for line in sorted(lines, key=lambda x: _url_key(x)):
        if not line.strip():
            continue
        url = _url_key(line)
        if url and url not in seen_urls:
            seen_urls.add(url)
            unique.append(line.strip())
    filepath.write_text('\n'.join(unique) + ('\n' if unique else ''))
    return len(unique)


# ── Raw log writer ────────────────────────────────────────────────────────────

def append_to_raw(filepath, tool_name: str, output: str):
    """Append raw tool output to domain raw log. Thread-safe."""
    filepath  = Path(filepath)
    timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    block = (
        f"\n\n{'='*60}\n"
        f"TOOL: {tool_name}  |  {timestamp}\n"
        f"{'='*60}\n"
        f"{output if output else '(no output)'}\n"
    )
    with _stdout_lock:
        with open(filepath, 'a', errors='replace') as fh:
            fh.write(block)


# ── Subdomain extraction ──────────────────────────────────────────────────────

def _clean_token(token: str) -> str:
    """Reduce a raw token to a bare hostname candidate (or '')."""
    token = token.strip('[](){}<>"\',` \t')
    if not token:
        return ""
    # Pull the host out of a URL.
    if '://' in token:
        token = token.split('://', 1)[1]
    token = token.split('/', 1)[0]      # drop any path
    token = token.split('@')[-1]        # drop userinfo
    token = token.split('?', 1)[0]
    # Strip a :port (but leave IPv6 bracketed forms alone — they aren't FQDNs).
    if token.count(':') == 1:
        token = token.split(':', 1)[0]
    token = re.sub(r'^\*\.', '', token)  # wildcard prefix
    return token.lower().rstrip('.')


def extract_subdomains(domain: str, text: str) -> list:
    """
    Extract valid subdomain FQDNs from arbitrary tool output.
    Handles mixed delimiters, wildcards, quotes, URLs, ports, mixed case.
    Only well-formed, in-scope RFC-1123 names are kept.
    Returns sorted deduplicated lowercase list.
    """
    domain_lower = domain.lower()
    results      = set()

    for line in text.splitlines():
        for raw_token in re.split(r'[\s,;|\t]+', line.strip()):
            token = _clean_token(raw_token)
            if not token:
                continue
            if token != domain_lower and not token.endswith(f'.{domain_lower}'):
                continue
            if _STRICT_FQDN.match(token):
                results.add(token)

    return sorted(results)


# ── Progress output ───────────────────────────────────────────────────────────

def print_domain_header(domain: str):
    bar = '=' * 62
    safe_print(f"\n{bar}")
    safe_print(f"  TARGET  {domain}")
    safe_print(f"{bar}")


def print_phase_header(name: str):
    pad = max(0, 52 - len(name))
    safe_print(f"\n  ── {name} " + "─" * pad)
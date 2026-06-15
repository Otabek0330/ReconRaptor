"""
modules/utils/output.py

Helpers for:
  · Creating per-domain output directories
  · Writing clean (sorted, deduped) result files
  · Appending raw tool output to the raw log
  · Extracting subdomain candidates from arbitrary tool output
  · Printing phase/domain headers to stdout
"""

import re
from pathlib import Path
from datetime import datetime


# ── Directory setup ───────────────────────────────────────────────────────────

def setup_domain_dir(domain: str, results_root: str | Path) -> Path:
    """Create and return the output directory for a single domain."""
    out_dir = Path(results_root) / domain
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


# ── File writers ──────────────────────────────────────────────────────────────

def write_clean(filepath: str | Path, lines) -> int:
    """
    Write a sorted, deduplicated list of non-empty lines.
    Returns the number of lines written.
    """
    filepath = Path(filepath)
    unique   = sorted({str(l).strip() for l in lines if str(l).strip()})
    filepath.write_text('\n'.join(unique) + ('\n' if unique else ''))
    return len(unique)


def append_to_raw(filepath: str | Path, tool_name: str, output: str):
    """
    Append raw tool output (stdout + stderr) to the domain's raw log file.
    Each section is separated by a header with the tool name and timestamp.
    """
    filepath  = Path(filepath)
    timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    with open(filepath, 'a', errors='replace') as fh:
        fh.write(f"\n\n{'='*60}\n")
        fh.write(f"TOOL: {tool_name}  |  {timestamp}\n")
        fh.write(f"{'='*60}\n")
        fh.write(output if output else "(no output)\n")


# ── Subdomain extraction ──────────────────────────────────────────────────────

def extract_subdomains(domain: str, text: str) -> list[str]:
    """
    Extract valid subdomain FQDNs from arbitrary tool output.

    Handles:
      · One token per line, or space/comma/pipe-separated tokens
      · Leading '*.' wildcard prefixes
      · Surrounding brackets, quotes, parentheses
      · Mixed-case output
      · Trailing dots

    Returns sorted, deduplicated list of lowercase FQDNs that are either
    equal to *domain* or end with '.*domain*'.
    """
    domain_lower = domain.lower()
    results      = set()

    for line in text.splitlines():
        # Split on common delimiters
        tokens = re.split(r'[\s,;|\t]+', line.strip())
        for token in tokens:
            # Strip surrounding punctuation
            token = token.strip('[](){}"\' \t')
            # Strip leading wildcard
            token = re.sub(r'^\*\.', '', token)
            # Lowercase + strip trailing dot
            token = token.lower().rstrip('.')

            if not token:
                continue

            if token == domain_lower or token.endswith(f'.{domain_lower}'):
                results.add(token)

    return sorted(results)


# ── Progress output ───────────────────────────────────────────────────────────

def print_domain_header(domain: str):
    bar = '=' * 62
    print(f"\n{bar}")
    print(f"  TARGET  {domain}")
    print(f"{bar}")


def print_phase_header(name: str):
    pad = max(0, 52 - len(name))
    print(f"\n  ── {name} " + "─" * pad)

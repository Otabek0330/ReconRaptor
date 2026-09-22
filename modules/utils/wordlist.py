"""
modules/utils/wordlist.py

Wordlist cleaning for two distinct use cases:

1. clean_wordlist()     — subdomain bruteforce labels (DNS RFC 1123)
2. clean_dir_wordlist() — directory traversal paths (permissive)

Memory optimization: writes directly to temp file line-by-line instead of
building a list then joining — halves peak RAM for 3M-entry wordlists.
"""

import re
import tempfile
from pathlib import Path

# RFC 1123 DNS label: [a-z0-9], 1-63 chars, hyphens allowed inside only
_LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$')


def _is_valid_label(word: str) -> bool:
    return bool(_LABEL_RE.match(word))


# ── Subdomain wordlist ────────────────────────────────────────────────────────

def clean_wordlist(path) -> tuple[str, int, int]:
    """
    Clean a subdomain bruteforce wordlist.

    Strips entries that are not valid RFC 1123 DNS labels.
    Writes directly to temp file (memory efficient for 3M+ entries).

    Returns:
        (temp_path, valid_count, stripped_count)

    Caller must delete the temp file when done.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")

    seen    = set()
    valid   = 0
    stripped = 0

    tmp = tempfile.NamedTemporaryFile(
        mode='w', suffix='.txt', delete=False, prefix='rr_wl_'
    )

    with open(path, 'r', errors='replace') as fh:
        for raw in fh:
            word = raw.strip().lower()
            if not word or word.startswith('#'):
                continue
            if not _is_valid_label(word):
                stripped += 1
                continue
            if word not in seen:
                seen.add(word)
                tmp.write(word + '\n')  # line-by-line, no join()
                valid += 1

    tmp.flush()
    tmp.close()
    return tmp.name, valid, stripped


# ── Directory traversal wordlist ──────────────────────────────────────────────

def clean_dir_wordlist(path) -> tuple[str, int, int]:
    """
    Clean a directory traversal wordlist.

    Rules are intentionally permissive — paths can contain /, ., -, _
    and mixed case. Only strips null bytes and overlong entries (>512 chars).
    Preserves original casing (tools handle case-sensitivity themselves).

    Returns:
        (temp_path, valid_count, stripped_count)
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Directory wordlist not found: {path}")

    seen    = set()
    valid   = 0
    stripped = 0

    tmp = tempfile.NamedTemporaryFile(
        mode='w', suffix='.txt', delete=False, prefix='rr_dir_wl_'
    )

    with open(path, 'r', errors='replace') as fh:
        for raw in fh:
            word = raw.rstrip('\n\r')
            stripped_word = word.strip()

            if not stripped_word or stripped_word.startswith('#'):
                continue
            if '\x00' in word or len(stripped_word) > 512:
                stripped += 1
                continue

            key = stripped_word.lower()
            if key not in seen:
                seen.add(key)
                tmp.write(stripped_word + '\n')
                valid += 1
            # Don't count duplicates as stripped — they're just removed

    tmp.flush()
    tmp.close()
    return tmp.name, valid, stripped


# ── Count helpers (no temp file) ─────────────────────────────────────────────

def count_valid(path) -> tuple[int, int]:
    """
    Count valid subdomain entries without writing a temp file.
    Used by preflight check.
    Returns (valid_count, total_non_blank_count).
    """
    path  = Path(path)
    total = 0
    valid = 0

    with open(path, 'r', errors='replace') as fh:
        for raw in fh:
            word = raw.strip()
            if not word or word.startswith('#'):
                continue
            total += 1
            if _is_valid_label(word.lower()):
                valid += 1

    return valid, total


def count_lines(path) -> int:
    """Count non-blank, non-comment lines in a file. Closes handle properly."""
    try:
        with open(path, 'r', errors='replace') as f:
            return sum(1 for line in f if line.strip() and not line.startswith('#'))
    except OSError:
        return 0

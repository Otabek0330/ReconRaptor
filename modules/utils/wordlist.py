"""
modules/utils/wordlist.py

Cleans any user-supplied wordlist before use:
  · Lowercase all entries
  · Strip entries that are not valid DNS labels (RFC 1123)
  · Deduplicate
  · Write cleaned list to a temporary file

Valid DNS label pattern:
  [a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?
  (1 to 63 characters; letters, digits, hyphens; no leading/trailing hyphen)
"""

import re
import tempfile
from pathlib import Path

# RFC 1123 label: starts/ends with alnum, contains only [a-z0-9-], 1-63 chars
_LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$')


def _is_valid_label(word: str) -> bool:
    return bool(_LABEL_RE.match(word))


def clean_wordlist(path: str | Path) -> tuple[str, int, int]:
    """
    Read wordlist at *path*, clean it, write a temp file.

    Returns:
        (temp_file_path, valid_count, stripped_count)

    The caller is responsible for deleting the temp file when done.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")

    seen    = set()
    valid   = []
    stripped = 0

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
                valid.append(word)

    tmp = tempfile.NamedTemporaryFile(
        mode='w', suffix='.txt', delete=False, prefix='rr_wl_'
    )
    tmp.write('\n'.join(valid))
    tmp.flush()
    tmp.close()

    return tmp.name, len(valid), stripped


def count_valid(path: str | Path) -> tuple[int, int]:
    """
    Count valid entries without writing a temp file.
    Used by the preflight check to display wordlist stats.

    Returns:
        (valid_count, total_count)  — total excludes blank/comment lines
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

"""
modules/core/config.py

Loads config.default.yaml (bundled defaults), deep-merges user's config.yaml.
Also provides domain FQDN validation used by scanner.py at input time.

What this version fixes vs the previous one
───────────────────────────────────────────
· validate_domain is stricter and IDN-aware (finding #21)
    - Rejects bare IP addresses (v4 and v6) — this is a subdomain-enum tool;
      an IP target is almost always a mistake and breaks every phase.
    - Rejects single-label inputs like 'localhost' or 'com' (a real target
      has at least two labels) and numeric TLDs.
    - Accepts internationalised domains by converting them to punycode
      (münchen.de → xn--mnchen-3ya.de) instead of rejecting them outright.

· validate_config checks the port-scan / traversal numbers too, so a bad
  value there is caught by `config --validate` rather than at scan time.
"""

import re
import sys
import shutil
import ipaddress
from pathlib import Path

try:
    import yaml
    YAML_OK = True
except ImportError:
    YAML_OK = False

BASE_DIR       = Path(__file__).parent.parent.parent
DEFAULT_CONFIG = BASE_DIR / "config.default.yaml"
USER_CONFIG    = BASE_DIR / "config.yaml"

_FQDN_RE = re.compile(
    r'^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)*'
    r'[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$'
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_yaml():
    if not YAML_OK:
        print("[!] pyyaml not installed. Run: pip install pyyaml")
        sys.exit(1)


def _deep_merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _is_ip_literal(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ── Domain validation ─────────────────────────────────────────────────────────

def validate_domain(raw: str) -> str:
    """
    Validate and normalise a domain string. Returns the cleaned domain
    (punycode for IDNs) or raises ValueError with a clear message.
    """
    domain = raw.strip()

    # Strip scheme if accidentally included
    for scheme in ("https://", "http://", "ftp://"):
        if domain.lower().startswith(scheme):
            domain = domain[len(scheme):]
            break

    # Reject paths / ports
    if '/' in domain:
        raise ValueError(
            f"Domain must not contain a path. Got: '{raw}'\n"
            f"  Did you mean: '{domain.split('/')[0]}'")
    if domain.count(':') == 1 and not domain.startswith('['):
        raise ValueError(f"Domain must not include a port. Got: '{raw}'")

    domain = domain.rstrip('.')
    if not domain:
        raise ValueError(f"Empty domain after cleaning: '{raw}'")

    # Convert IDNs to punycode so the ASCII FQDN check can pass.
    if any(ord(c) > 127 for c in domain):
        try:
            domain = domain.encode('idna').decode('ascii')
        except (UnicodeError, Exception):
            raise ValueError(f"Invalid internationalised domain: '{raw}'")

    domain = domain.lower()

    if len(domain) > 253:
        raise ValueError(f"Domain too long ({len(domain)} chars): '{domain}'")

    # Reject IP literals — this tool enumerates DNS names, not hosts.
    if _is_ip_literal(domain):
        raise ValueError(
            f"'{raw}' is an IP address, not a domain. Recon Raptor enumerates "
            f"DNS names — give it a domain like example.com.")

    # Require at least two labels (rejects 'localhost', 'com').
    if '.' not in domain:
        raise ValueError(
            f"'{raw}' has only one label. Expected a domain with a TLD, "
            f"e.g. example.com.")

    if domain.rsplit('.', 1)[-1].isdigit():
        raise ValueError(f"Invalid TLD (all-numeric) in: '{domain}'")

    if not _FQDN_RE.match(domain):
        raise ValueError(
            f"Invalid domain format: '{domain}'\n"
            f"  Expected labels separated by dots, letters/digits/hyphens only")

    return domain


# ── Public API ────────────────────────────────────────────────────────────────

def load_config(path=None) -> dict:
    """Load config: start from defaults, deep-merge user config on top."""
    _require_yaml()

    if not DEFAULT_CONFIG.exists():
        print(f"[!] Bundled default config not found: {DEFAULT_CONFIG}")
        sys.exit(1)

    with open(DEFAULT_CONFIG, 'r') as f:
        config = yaml.safe_load(f) or {}

    user_path = Path(path) if path else USER_CONFIG

    if user_path.exists():
        with open(user_path, 'r') as f:
            user_cfg = yaml.safe_load(f) or {}
        config = _deep_merge(config, user_cfg)
    else:
        if path:
            print(f"[!] Config file not found: {path}")
            sys.exit(1)
        else:
            print("[i] No config.yaml found — using defaults.", file=sys.stderr)
            print("    Run `recon_raptor config --init` to create one.\n", file=sys.stderr)

    config['_config_path'] = str(user_path if user_path.exists() else DEFAULT_CONFIG)
    return config


def init_config():
    if USER_CONFIG.exists():
        print(f"[!] config.yaml already exists: {USER_CONFIG}")
        print("    Delete it first to reset to defaults.")
        return
    shutil.copy(DEFAULT_CONFIG, USER_CONFIG)
    print(f"[+] Created: {USER_CONFIG}")
    print("    Edit it to set wordlist, dir_wordlist, API tokens, etc.")
    print("    Validate with: recon_raptor config --validate")
    print()
    print("    [!] config.yaml may contain API tokens.")
    print("        Do NOT commit it to version control.")


def validate_config(config: dict):
    errors, warnings = [], []

    resolvers = Path(config.get('resolvers', ''))
    if not resolvers.exists():
        errors.append(f"resolvers file not found: {resolvers}")

    wordlist = config.get('wordlist', '') or ''
    if wordlist:
        if not Path(wordlist).exists():
            errors.append(f"wordlist not found: {wordlist}")
    else:
        warnings.append("No wordlist set — subdomain bruteforce will be skipped")

    dir_wordlist = config.get('dir_wordlist', '') or ''
    if dir_wordlist:
        if not Path(dir_wordlist).exists():
            errors.append(f"dir_wordlist not found: {dir_wordlist}")
    else:
        warnings.append("No dir_wordlist set — directory traversal will be skipped")

    output_dir = Path(config.get('output_dir', './results'))
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        errors.append(f"Cannot write to output_dir: {output_dir}")

    for key in ['threads', 'brute_threads', 'rate', 'timeout', 'depth',
                'traversal_jobs']:
        val = config.get(key)
        if val is not None and (not isinstance(val, (int, float)) or val <= 0):
            errors.append(f"'{key}' must be a positive number, got: {val!r}")

    ps = config.get('port_scan', {}) or {}
    for key in ['top_ports', 'rate']:
        val = ps.get(key)
        if val is not None and (not isinstance(val, (int, float)) or val <= 0):
            errors.append(f"port_scan.{key} must be a positive number, got: {val!r}")

    if errors:
        print("\n[!] Config errors:")
        for e in errors:
            print(f"    ✗  {e}")
    if warnings:
        print("\n[i] Config warnings:")
        for w in warnings:
            print(f"    !  {w}")
    if not errors and not warnings:
        print("[+] Config looks good.")
    elif not errors:
        print("\n[+] No errors (warnings are informational).")
    else:
        print("\n[-] Fix errors above before running scans.")
        sys.exit(1)
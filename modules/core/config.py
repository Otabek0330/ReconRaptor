"""
modules/core/config.py

Loads config.default.yaml (bundled defaults), then deep-merges the user's
config.yaml on top. The user's file only needs to contain values they want
to override — missing keys fall back to defaults.
"""

import sys
import shutil
from pathlib import Path

try:
    import yaml
    YAML_OK = True
except ImportError:
    YAML_OK = False

BASE_DIR = Path(__file__).parent.parent.parent   # recon_raptor root
DEFAULT_CONFIG  = BASE_DIR / "config.default.yaml"
USER_CONFIG     = BASE_DIR / "config.yaml"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_yaml():
    if not YAML_OK:
        print("[!] pyyaml is not installed.")
        print("    Run:  pip install pyyaml")
        print("    Or:   sudo recon_raptor install")
        sys.exit(1)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, returning a new dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ── Public API ────────────────────────────────────────────────────────────────

def load_config(path=None) -> dict:
    """
    Load configuration. Always starts from config.default.yaml, then
    deep-merges config.yaml (or the path the user passed via --config).
    """
    _require_yaml()

    if not DEFAULT_CONFIG.exists():
        print(f"[!] Bundled default config not found: {DEFAULT_CONFIG}")
        print("    Your Recon Raptor installation may be incomplete.")
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
            # User explicitly asked for a file that doesn't exist
            print(f"[!] Config file not found: {path}")
            sys.exit(1)
        else:
            print(f"[i] No config.yaml found — using defaults.")
            print(f"    Run `recon_raptor config --init` to create one.\n")

    return config


def init_config():
    """Copy config.default.yaml to config.yaml in the project root."""
    if USER_CONFIG.exists():
        print(f"[!] config.yaml already exists at: {USER_CONFIG}")
        print(f"    Delete it first if you want to reset to defaults.")
        return

    shutil.copy(DEFAULT_CONFIG, USER_CONFIG)
    print(f"[+] Created: {USER_CONFIG}")
    print(f"    Edit it to set your wordlist path, API tokens, and preferences.")
    print(f"    Validate it with: recon_raptor config --validate")


def validate_config(config: dict):
    """Validate config values and print any errors or warnings."""
    errors   = []
    warnings = []

    # resolvers
    resolvers = Path(config.get('resolvers', ''))
    if not resolvers.exists():
        errors.append(f"resolvers file not found: {resolvers}")

    # wordlist
    wordlist = config.get('wordlist', '')
    if wordlist:
        if not Path(wordlist).exists():
            errors.append(f"wordlist not found: {wordlist}")
    else:
        warnings.append("No wordlist set — bruteforce phase will be skipped")

    # output_dir writable
    output_dir = Path(config.get('output_dir', './results'))
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        errors.append(f"Cannot write to output_dir: {output_dir}")

    # numeric sanity
    for key in ['threads', 'rate', 'timeout', 'depth']:
        val = config.get(key)
        if not isinstance(val, (int, float)) or val <= 0:
            errors.append(f"'{key}' must be a positive number, got: {val!r}")

    # ports list
    ports = config.get('ports', [])
    if not isinstance(ports, list) or not ports:
        warnings.append("'ports' is empty — HTTP probe will use defaults")

    # Print results
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
        print("\n[+] No errors (warnings above are informational).")
    else:
        print("\n[-] Fix the errors above before running scans.")
        sys.exit(1)

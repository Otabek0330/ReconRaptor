"""
modules/core/preflight.py

Detects which tools are installed, checks config files and the wordlist,
then prints a formatted capability table.  Called by `recon_raptor check`
and also at the start of every scan to know which tools to use.
"""

import re
import shutil
import subprocess
import platform
from pathlib import Path

# ── Tool catalogue ────────────────────────────────────────────────────────────
# (name, version_command, is_required, description)
TOOL_GROUPS = {
    "Core enumeration": [
        ("subfinder",   ["subfinder",   "-version"],  True,  "passive subdomain discovery"),
        ("assetfinder", ["assetfinder", "--help"],    True,  "passive subdomain discovery"),
        ("findomain",   ["findomain",   "--version"], False, "passive subdomain discovery"),
        ("puredns",     ["puredns",     "-v"],        True,  "DNS bruteforce + wildcard filter"),
        ("massdns",     ["massdns",     "--version"], True,  "high-performance DNS resolver (puredns backend)"),
    ],
    "Resolution & probing": [
        ("dnsx",  ["dnsx",  "-version"], True, "multi-record DNS resolution"),
        ("httpx", ["httpx", "-version"], True, "HTTP probing + fingerprinting"),
    ],
    "Directory traversal": [
        ("gobuster",  ["gobuster",  "version"],  True,  "directory/vhost bruteforce"),
        ("dirsearch", ["dirsearch", "--version"], False, "recursive web path scanner"),
        ("ffuf",      ["ffuf",      "-V"],        False, "web fuzzer"),
    ],
    "Optional extras": [
        ("gowitness", ["gowitness", "version"],  False, "screenshot capture"),
        ("gau",       ["gau",       "--version"], False, "wayback Machine URL harvesting"),
        ("nuclei",    ["nuclei",    "-version"],  False, "template-based vulnerability scanning"),
    ],
}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _get_version(cmd: list) -> str | None:
    """Run a version command and return the version string, or None if missing."""
    if not shutil.which(cmd[0]):
        return None
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5
        )
        output = (result.stdout + result.stderr).strip()
        match = re.search(r'v?\d+\.\d+[\.\d]*', output)
        return match.group(0) if match else "found"
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError):
        return None


def _get_os_info() -> tuple[str, str]:
    """Return (os_description, package_manager)."""
    system = platform.system()
    machine = platform.machine()

    if system == "Darwin":
        os_str = f"macOS {platform.mac_ver()[0]}  ·  {machine}"
    elif system == "Linux":
        try:
            release = Path("/etc/os-release").read_text()
            m = re.search(r'^PRETTY_NAME="(.+)"', release, re.M)
            os_str = f"{m.group(1)}  ·  {machine}" if m else f"Linux  ·  {machine}"
        except OSError:
            os_str = f"Linux  ·  {machine}"
    else:
        os_str = f"{system}  ·  {machine}"

    pkg_mgr = "unknown"
    for pm in ["apt", "dnf", "yum", "pacman", "apk", "zypper", "brew"]:
        if shutil.which(pm):
            pkg_mgr = pm
            break

    return os_str, pkg_mgr


# ── Public API ────────────────────────────────────────────────────────────────

def detect_tools() -> dict:
    """
    Return {tool_name: version_string_or_None} for every tool in the catalogue.
    Used both by `check` and by the scanner to decide which tools to call.
    """
    results = {}
    for _section, tools in TOOL_GROUPS.items():
        for name, cmd, _required, _desc in tools:
            results[name] = _get_version(cmd)
    return results


def check_files(config: dict) -> list[tuple[str, bool, str]]:
    """
    Check config files, resolvers, and wordlist.
    Returns list of (label, ok: bool, note: str).
    """
    issues = []

    # config.yaml
    from pathlib import Path as P
    cfg_path = P(__file__).parent.parent.parent / "config.yaml"
    issues.append(("config.yaml", cfg_path.exists(),
                   "found" if cfg_path.exists() else "not found — run: recon_raptor config --init"))

    # resolvers.txt
    resolvers = Path(config.get('resolvers', './resolvers.txt'))
    if resolvers.exists():
        count = sum(
            1 for line in resolvers.read_text().splitlines()
            if line.strip() and not line.startswith('#')
        )
        issues.append(("resolvers.txt", True, f"{count} entries"))
    else:
        issues.append(("resolvers.txt", False, f"not found: {resolvers}"))

    # wordlist
    wordlist = config.get('wordlist', '')
    if wordlist:
        wl_path = Path(wordlist)
        if wl_path.exists():
            from modules.utils.wordlist import count_valid
            valid, total = count_valid(wl_path)
            stripped = total - valid
            note = f"{valid:,} valid entries"
            if stripped:
                note += f"  ({stripped} DNS-invalid stripped)"
            issues.append(("wordlist", True, note))
        else:
            issues.append(("wordlist", False, f"not found: {wordlist}"))
    else:
        issues.append(("wordlist", False, "not configured — bruteforce will be skipped"))

    return issues


def run_check(config: dict):
    """Print the full capability table. Called by `recon_raptor check`."""
    os_str, pkg_mgr = _get_os_info()

    print(f"\n  System        {os_str}")
    print(f"  Package mgr   {pkg_mgr}\n")

    tool_status = detect_tools()
    ready   = 0
    missing = 0

    for section, tools in TOOL_GROUPS.items():
        bar_len = max(0, 46 - len(section))
        print(f"  ─── {section} " + "─" * bar_len)
        for name, _cmd, required, _desc in tools:
            version = tool_status.get(name)
            if version:
                print(f"  ✓  {name:<16} {version}")
                ready += 1
            else:
                tag = "required" if required else "optional"
                print(f"  ✗  {name:<16} not found  [{tag}]")
                missing += 1
        print()

    print("  ─── Config & files " + "─" * 30)
    for label, ok, note in check_files(config):
        icon = "✓" if ok else "✗"
        print(f"  {icon}  {label:<16} {note}")

    print(f"\n  {ready} ready  ·  {missing} missing\n")

    if missing > 0:
        print("  To install missing tools:")
        print("    sudo recon_raptor install")
        print("    sudo recon_raptor install --exclude gowitness,gau,nuclei")
        print("    recon_raptor install --dry-run   (preview without sudo)")

    print()
    return tool_status

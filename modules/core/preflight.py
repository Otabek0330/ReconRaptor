"""
modules/core/preflight.py

Detects installed tools and prints the capability table.
Called by `recon_raptor check` and at the start of every scan.

What this version fixes vs the previous one
───────────────────────────────────────────
· Parallel detection (finding #44)
    detect_tools() ran ~15 version checks strictly one after another at the
    start of every scan. They now run in a small thread pool, so startup
    isn't dominated by serial subprocess spawns.

· Apple-Silicon Homebrew path
    /opt/homebrew/bin is now a known bin dir, matching utils/process.py, so
    tools installed by brew on arm64 macOS resolve consistently.

· httpx identity note (finding #11)
    `check` now flags when the httpx on PATH doesn't look like
    ProjectDiscovery's (the python3-httpx package can shadow it on
    Kali/Debian), which otherwise shows up as "installed" but produces zero
    live hosts at scan time.

Note: because utils/process.run_cmd now resolves bare tool names against
PATH *and* these known dirs before executing, detection and execution
finally agree — the secure_path mismatch (finding #2) no longer causes a
detected tool to fail at run time.
"""

import os
import re
import shutil
import platform
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from modules.utils.process import run_cmd

# Kept in sync with utils/process._KNOWN_BIN_DIRS.
_KNOWN_BIN_DIRS = ["/usr/local/bin", "/usr/local/sbin", "/opt/homebrew/bin"]

TOOL_GROUPS = {
    "Core enumeration": [
        ("subfinder",   ["subfinder",   "-version"], True,  "passive subdomain discovery"),
        ("assetfinder", ["assetfinder", "--help"],   True,  "passive subdomain discovery"),
        ("findomain",   ["findomain",   "--version"],False, "passive subdomain discovery"),
        ("puredns",     ["puredns",     "-v"],       True,  "DNS bruteforce + wildcard filter"),
        ("massdns",     ["massdns",     "--version"],True,  "puredns backend resolver"),
    ],
    "Resolution & probing": [
        ("dnsx",  ["dnsx",  "-version"], True, "multi-record DNS resolution"),
        ("httpx", ["httpx", "-version"], True, "HTTP probing + fingerprinting"),
    ],
    "Port scanning": [
        ("naabu", ["naabu", "-version"], False, "fast port scanner"),
    ],
    "Directory traversal": [
        ("gobuster",  ["gobuster",  "version"],   True,  "directory/vhost bruteforce"),
        ("dirsearch", ["dirsearch", "--version"], False, "recursive web path scanner"),
        ("ffuf",      ["ffuf",      "-V"],         False, "web fuzzer"),
    ],
    "Optional extras": [
        ("gowitness", ["gowitness", "version"],  False, "screenshot capture"),
        ("gau",       ["gau",       "--version"], False, "wayback URL harvesting"),
        ("nuclei",    ["nuclei",    "-version"],  False, "vuln scanning"),
        ("dig",       ["dig",       "-v"],         False, "zone transfer (AXFR)"),
    ],
}


def resolve_tool(name: str):
    """
    Find a tool's actual path, independent of the calling process's PATH.

    shutil.which() first; on failure (e.g. sudo secure_path excludes
    /usr/local/bin) fall back to our known install dirs.
    """
    found = shutil.which(name)
    if found:
        return found
    for d in _KNOWN_BIN_DIRS:
        candidate = Path(d) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _get_version(cmd: list):
    resolved = resolve_tool(cmd[0])
    if not resolved:
        return None
    full_cmd = [resolved] + cmd[1:]
    stdout, stderr, _ = run_cmd(full_cmd, timeout=5)
    combined = (stdout + stderr).strip()
    m = re.search(r'v?\d+\.\d+[\.\d]*', combined)
    return m.group(0) if m else "found"


def _httpx_identity_ok() -> bool:
    """
    True if the httpx on PATH looks like ProjectDiscovery's. Conservative:
    only False when fairly confident it's the wrong tool.
    """
    resolved = resolve_tool("httpx")
    if not resolved:
        return True   # nothing to warn about; absence handled elsewhere
    stdout, stderr, rc = run_cmd([resolved, "-version"], timeout=6)
    combined = (stdout + stderr).lower()
    if "projectdiscovery" in combined:
        return True
    if rc == 0 and re.search(r'v?\d+\.\d+\.\d+', combined):
        return True
    bad_markers = ("usage:", "unrecognized arguments", "no such option",
                   "flag provided but not defined")
    if any(m in combined for m in bad_markers):
        return False
    return True


def _get_os_info():
    system  = platform.system()
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


def detect_tools() -> dict:
    """Return {tool_name: version_or_None} for every catalogued tool.

    Version checks run in parallel — they're independent subprocess spawns,
    so serialising ~15 of them needlessly slowed every scan's startup.
    """
    tasks = [(name, cmd)
             for _section, tools in TOOL_GROUPS.items()
             for name, cmd, _req, _desc in tools]

    results = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_get_version, cmd): name for name, cmd in tasks}
        for fut in futures:
            results[futures[fut]] = fut.result()
    return results


def check_files(config: dict, config_path: str = None) -> list:
    """Check config, resolvers, wordlists. Returns [(label, ok, note)]."""
    issues = []

    cp = Path(config.get('_config_path', '') or config_path or
              (Path(__file__).parent.parent.parent / "config.yaml"))
    issues.append(("config.yaml", cp.exists(),
                   f"found ({cp})" if cp.exists()
                   else "not found — run: recon_raptor config --init"))

    resolvers = Path(config.get('resolvers', './resolvers.txt'))
    if resolvers.exists():
        with open(resolvers) as f:
            count = sum(1 for l in f if l.strip() and not l.startswith('#'))
        issues.append(("resolvers.txt", True, f"{count} entries"))
    else:
        issues.append(("resolvers.txt", False, f"not found: {resolvers}"))

    wordlist = config.get('wordlist', '') or ''
    if wordlist and Path(wordlist).exists():
        from modules.utils.wordlist import count_valid
        valid, total = count_valid(wordlist)
        stripped = total - valid
        note = f"{valid:,} valid entries"
        if stripped:
            note += f"  ({stripped} DNS-invalid stripped)"
        issues.append(("wordlist (sub)", True, note))
    elif wordlist:
        issues.append(("wordlist (sub)", False, f"not found: {wordlist}"))
    else:
        issues.append(("wordlist (sub)", False, "not set — bruteforce skipped"))

    dir_wl = config.get('dir_wordlist', '') or ''
    if dir_wl and Path(dir_wl).exists():
        from modules.utils.wordlist import count_lines
        count = count_lines(dir_wl)
        issues.append(("wordlist (dir)", True, f"{count:,} entries"))
    elif dir_wl:
        issues.append(("wordlist (dir)", False, f"not found: {dir_wl}"))
    else:
        issues.append(("wordlist (dir)", False, "not set — dir traversal skipped"))

    return issues


def run_check(config: dict):
    """Print the full capability table."""
    os_str, pkg_mgr = _get_os_info()
    print(f"\n  System        {os_str}")
    print(f"  Package mgr   {pkg_mgr}\n")

    if os.geteuid() == 0 and os.environ.get("SUDO_USER"):
        path_env = os.environ.get("PATH", "")
        if "/usr/local/bin" not in path_env.split(":"):
            print("  ⚠  /usr/local/bin is NOT in sudo's PATH on this system.")
            print("     Tools this installer places there still work (execution")
            print("     resolves them directly), but plain 'sudo <tool>' won't.")
            print("     Fix with: sudo visudo → add /usr/local/bin to secure_path\n")

    tool_status = detect_tools()
    ready = missing = 0

    for section, tools in TOOL_GROUPS.items():
        bar_len = max(0, 46 - len(section))
        print(f"  ─── {section} " + "─" * bar_len)
        for name, _cmd, required, _desc in tools:
            version = tool_status.get(name)
            if version:
                path = resolve_tool(name) or "?"
                flag = "" if any(path.startswith(d) for d in _KNOWN_BIN_DIRS) \
                    else f"  ⚠ {path}"
                print(f"  ✓  {name:<16} {version}{flag}")
                ready += 1
            else:
                tag = "required" if required else "optional"
                print(f"  ✗  {name:<16} not found  [{tag}]")
                missing += 1
        print()

    # httpx identity note (finding #11)
    if tool_status.get("httpx") and not _httpx_identity_ok():
        print("  ⚠  httpx is present but does not look like ProjectDiscovery's httpx.")
        print("     The python3-httpx package can shadow it on Kali/Debian, which")
        print("     makes the HTTP probe return 0 live hosts. Reinstall PD httpx:")
        print("       go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n")

    print("  ─── Config & files " + "─" * 30)
    for label, ok, note in check_files(config):
        icon = "✓" if ok else "✗"
        print(f"  {icon}  {label:<18} {note}")

    print(f"\n  {ready} ready  ·  {missing} missing\n")
    if missing > 0:
        print("  To install missing tools:")
        print("    sudo recon_raptor install")
        print("    sudo recon_raptor install --exclude gowitness,gau,nuclei")
        print("    recon_raptor install --dry-run   (preview without sudo)\n")

    return tool_status


# ── Phase ↔ tool registry (single source of truth) ────────────────────────────
# Used by `recon_raptor list --tools`, the scan --only flag, and --skip-* flags.
# Each entry: key (config phase key), label, tools it uses (empty = built-in,
# no external tool needed), the --skip-* flag name, and CLI aliases for --only.
PHASE_DEFS = [
    {"key": "passive_enum",   "label": "Passive subdomain enum",
     "tools": ["subfinder", "assetfinder", "findomain"], "builtin": "crt.sh",
     "skip": "--skip-passive",
     "aliases": ["passive", "subfinder", "assetfinder", "findomain", "crtsh", "crt.sh"]},
    {"key": "bruteforce",     "label": "Subdomain bruteforce",
     "tools": ["puredns", "massdns", "dnsx"], "builtin": "",
     "skip": "--skip-brute",
     "aliases": ["brute", "puredns", "massdns"]},
    {"key": "dns_resolve",    "label": "DNS resolution (+ _dmarc/DKIM, AXFR)",
     "tools": ["dnsx", "dig"], "builtin": "",
     "skip": "--skip-resolve",
     "aliases": ["dns", "resolve", "resolver", "dnsx"]},
    {"key": "port_scan",      "label": "Port scanning (public IPs)",
     "tools": ["naabu"], "builtin": "",
     "skip": "--skip-ports",
     "aliases": ["ports", "port", "portscan", "naabu"]},
    {"key": "http_probe",     "label": "HTTP probe",
     "tools": ["httpx"], "builtin": "",
     "skip": "--skip-http",
     "aliases": ["http", "probe", "httpx", "alive"]},
    {"key": "traversal",      "label": "Directory traversal",
     "tools": ["ffuf", "gobuster", "dirsearch"], "builtin": "",
     "skip": "--skip-traversal",
     "aliases": ["dirs", "dir", "directory", "fuzz", "ffuf", "gobuster", "dirsearch"]},
    {"key": "ip_enrichment",  "label": "IP enrichment (CDN vs cloud)",
     "tools": [], "builtin": "ipinfo MMDB / ip-api.com",
     "skip": "--skip-enrich",
     "aliases": ["enrich", "enrichment", "ip", "geoip"]},
    {"key": "harvest",        "label": "Web path harvest (robots/sitemap)",
     "tools": [], "builtin": "built-in",
     "skip": "--skip-harvest",
     "aliases": ["harvest", "robots", "sitemap"]},
    {"key": "email_security", "label": "Email security (SPF/DMARC/DKIM)",
     "tools": [], "builtin": "built-in",
     "skip": "--skip-email",
     "aliases": ["email", "spf", "dmarc", "dkim", "mail"]},
]

# Virtual group: enumeration = passive + brute together.
_PHASE_GROUPS = {
    "subdomain_enum": ["passive_enum", "bruteforce"],
    "subs":           ["passive_enum", "bruteforce"],
    "subdomains":     ["passive_enum", "bruteforce"],
    "enum":           ["passive_enum", "bruteforce"],
}

_PHASE_KEYS = [p["key"] for p in PHASE_DEFS]


def _build_alias_map() -> dict:
    amap = {}
    for p in PHASE_DEFS:
        amap[p["key"]] = [p["key"]]
        for a in p["aliases"]:
            amap[a] = [p["key"]]
    for name, keys in _PHASE_GROUPS.items():
        amap[name] = keys
    return amap


_PHASE_ALIAS = _build_alias_map()


def resolve_phase_names(names):
    """
    Map a list of user-supplied phase/tool names to canonical phase keys.
    Returns (keys_set, unknown_list). Case/space/underscore/hyphen-insensitive.
    """
    keys, unknown = set(), []
    for raw in names:
        norm = raw.strip().lower().replace("-", "_").replace(" ", "_")
        alt  = norm.replace("_", "")
        matched = _PHASE_ALIAS.get(norm) or _PHASE_ALIAS.get(alt)
        if matched:
            keys.update(matched)
        else:
            unknown.append(raw)
    return keys, unknown


def phase_names_help() -> str:
    """One-line list of accepted --only names, for error messages."""
    return ", ".join(_PHASE_KEYS + ["subdomain_enum"])


def run_list_tools(config: dict = None):
    """`recon_raptor list --tools` — show phases, their tools, and status."""
    status = detect_tools()

    print("\n  Phases run in this order. Use the names below with --only or --skip-*.\n")
    header = f"  {'PHASE':<16} {'STATUS':<9} TOOLS / SOURCE"
    print(header)
    print("  " + "─" * (len(header) - 2))

    for p in PHASE_DEFS:
        tools = p["tools"]
        if tools:
            have = [t for t in tools if status.get(t)]
            # A phase is runnable if it has at least one usable tool.
            # bruteforce/traversal need any one; others need their listed tool.
            if p["key"] in ("passive_enum", "traversal"):
                ok = len(have) > 0
            elif p["key"] == "bruteforce":
                ok = (status.get("puredns") and status.get("massdns")) or status.get("dnsx")
            else:
                ok = all(status.get(t) for t in tools)
            state = " ready  " if ok else "MISSING "
            parts = []
            for t in tools:
                parts.append(f"{t}{'✓' if status.get(t) else '✗'}")
            src = "  ".join(parts)
            if p["builtin"]:
                src += f"  (+ {p['builtin']})"
        else:
            state = " ready  "
            src = f"{p['builtin']} (no external tool)"
        print(f"  {p['key']:<16} [{state}] {src}")

    print("\n  Examples:")
    print("    recon_raptor scan -d example.com --only traversal")
    print("    recon_raptor scan -d example.com --only passive,http_probe")
    print("    recon_raptor scan -d example.com --skip-ports --skip-traversal")
    print("\n  --only reuses existing result files for phases it doesn't run,")
    print("  so run a full scan once, then re-run a single phase with --only.\n")
    return status
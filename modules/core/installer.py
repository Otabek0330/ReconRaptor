"""
modules/core/installer.py

OS-aware tool installer for Recon Raptor.

Fixes applied vs v1:
  · Smart asset picker  — keyword matching handles version-embedded filenames
                          e.g. "puredns_2.1.6_Linux_amd64.tar.gz" is now found
                          without needing to know the version in advance.
  · pip handling        — dirsearch and any future pip tools are installed
                          directly via sys.executable, not through install_via_pm.
  · GitHub rate limits  — detects 403/rate-limit JSON, adds 0.8 s delay between
                          API calls, prints a clear message when limited.
  · Better diagnostics  — on match failure, prints the first 5 actual asset
                          names so the user knows what was available.
"""

import os
import sys
import shutil
import platform
import subprocess
import tempfile
import zipfile
import tarfile
import stat
import time
from pathlib import Path

try:
    import requests as _req
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

BASE_DIR = Path(__file__).parent.parent.parent
BIN_DIR  = Path("/usr/local/bin")


# ── Tool catalogue ────────────────────────────────────────────────────────────
# Asset patterns are NO LONGER stored here — the smart picker figures them
# out from the actual GitHub release assets at install time.

TOOLS = {
    "subfinder": {
        "required": True, "optional": False,
        "description": "passive subdomain enumeration",
        "github_repo": "projectdiscovery/subfinder",
        "binary_name": "subfinder",
        "apt": None, "dnf": None, "pacman": None, "brew": "subfinder",
    },
    "assetfinder": {
        "required": True, "optional": False,
        "description": "passive subdomain enumeration",
        "github_repo": "tomnomnom/assetfinder",
        "binary_name": "assetfinder",
        "apt": None, "dnf": None, "pacman": None, "brew": None,
    },
    "findomain": {
        "required": False, "optional": False,
        "description": "passive subdomain enumeration",
        "github_repo": "findomain/findomain",
        "binary_name": "findomain",
        "apt": None, "dnf": None, "pacman": None, "brew": "findomain",
    },
    "puredns": {
        "required": True, "optional": False,
        "description": "DNS bruteforce + wildcard filtering",
        "github_repo": "d3mondev/puredns",
        "binary_name": "puredns",
        "apt": None, "dnf": None, "pacman": None, "brew": None,
    },
    "massdns": {
        "required": True, "optional": False,
        "description": "high-performance DNS resolver (puredns backend)",
        "github_repo": "blechschmidt/massdns",
        "binary_name": "massdns",
        "apt": "massdns", "dnf": None, "pacman": "massdns", "brew": "massdns",
    },
    "dnsx": {
        "required": True, "optional": False,
        "description": "multi-record DNS resolution",
        "github_repo": "projectdiscovery/dnsx",
        "binary_name": "dnsx",
        "apt": None, "dnf": None, "pacman": None, "brew": "dnsx",
    },
    "httpx": {
        "required": True, "optional": False,
        "description": "HTTP probing and fingerprinting",
        "github_repo": "projectdiscovery/httpx",
        "binary_name": "httpx",
        "apt": None, "dnf": None, "pacman": None, "brew": "httpx",
    },
    "gobuster": {
        "required": True, "optional": False,
        "description": "directory and vhost bruteforce",
        "github_repo": "OJ/gobuster",
        "binary_name": "gobuster",
        "apt": "gobuster", "dnf": None, "pacman": "gobuster", "brew": "gobuster",
    },
    "dirsearch": {
        "required": False, "optional": False,
        "description": "recursive web path scanner",
        "pip": "dirsearch",           # installed via pip, not GitHub
        "binary_name": "dirsearch",
    },
    "ffuf": {
        "required": False, "optional": False,
        "description": "web fuzzer",
        "github_repo": "ffuf/ffuf",
        "binary_name": "ffuf",
        "apt": None, "dnf": None, "pacman": "ffuf", "brew": "ffuf",
    },
    "gowitness": {
        "required": False, "optional": True,
        "description": "screenshot capture",
        "github_repo": "sensepost/gowitness",
        "binary_name": "gowitness",
        "apt": None, "dnf": None, "pacman": None, "brew": None,
    },
    "gau": {
        "required": False, "optional": True,
        "description": "wayback Machine URL harvesting",
        "github_repo": "lc/gau",
        "binary_name": "gau",
        "apt": None, "dnf": None, "pacman": None, "brew": "gau",
    },
    "nuclei": {
        "required": False, "optional": True,
        "description": "template-based vulnerability scanning",
        "github_repo": "projectdiscovery/nuclei",
        "binary_name": "nuclei",
        "apt": None, "dnf": None, "pacman": None, "brew": "nuclei",
    },
}


# ── Sudo enforcement ──────────────────────────────────────────────────────────

def require_sudo():
    if os.geteuid() != 0:
        print("""
[!]  recon_raptor install requires root privileges.

     The installer needs sudo to:
       · Install system packages via apt / dnf / pacman / brew
       · Place tool binaries in /usr/local/bin
       · Create the recon_raptor symlink in /usr/local/bin

     Run with sudo:
       sudo recon_raptor install --all
       sudo recon_raptor install --exclude gowitness,nuclei

     Don't want to use sudo?
       Use --dry-run to preview every command, then run them yourself:
       recon_raptor install --dry-run

     The following commands never require sudo:
       recon_raptor scan · check · config
""")
        sys.exit(1)


def get_real_user() -> tuple[str, Path]:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        try:
            pw = pwd.getpwnam(sudo_user)
            return pw.pw_name, Path(pw.pw_dir)
        except KeyError:
            pass
    return "root", Path("/root")


# ── OS detection ──────────────────────────────────────────────────────────────

def detect_os() -> tuple[str, str | None]:
    system = platform.system()

    if system == "Darwin":
        return "macos", "brew" if shutil.which("brew") else None

    if system == "Linux":
        try:
            proc_ver = Path("/proc/version").read_text().lower()
            if "microsoft" in proc_ver:
                print("[i] WSL detected — treating as Linux")
        except OSError:
            pass

        try:
            release = Path("/etc/os-release").read_text().lower()
        except OSError:
            return "linux", _fallback_pm()

        if any(d in release for d in ["ubuntu", "debian", "kali", "parrot", "mint", "pop"]):
            return "debian", "apt"
        if any(d in release for d in ["fedora", "rhel", "rocky", "alma", "centos", "red hat"]):
            return "rhel", "dnf" if shutil.which("dnf") else "yum"
        if any(d in release for d in ["arch", "manjaro", "blackarch", "garuda", "endeavour"]):
            return "arch", "pacman"
        if "alpine" in release:
            return "alpine", "apk"
        if "opensuse" in release:
            return "suse", "zypper"

        return "linux", _fallback_pm()

    return "unknown", None


def _fallback_pm() -> str | None:
    for pm in ["apt", "dnf", "yum", "pacman", "apk", "zypper", "brew"]:
        if shutil.which(pm):
            return pm
    return None


# ── Connectivity ──────────────────────────────────────────────────────────────

def check_connectivity(dry_run: bool = False):
    if dry_run:
        print("[dry-run] connectivity check: https://github.com")
        return
    try:
        if _REQUESTS:
            _req.get("https://github.com", timeout=5)
        else:
            subprocess.run(
                ["curl", "-s", "--head", "https://github.com", "--max-time", "5"],
                capture_output=True, check=True
            )
    except Exception:
        print("[!] No internet connection — cannot download tool binaries.")
        sys.exit(1)


def get_arch() -> str:
    return {
        "x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64",
        "armv7l": "armv7", "i686": "386", "i386": "386",
    }.get(platform.machine(), "amd64")


# ── Smart asset picker ────────────────────────────────────────────────────────
# No hardcoded filenames. Uses keyword matching on OS and architecture so
# version-embedded names like "puredns_2.1.6_Linux_amd64.tar.gz" are found
# without knowing the version in advance.

_OS_KEYS = {
    "linux": ["linux"],
    "macos": ["darwin", "macos", "mac", "osx"],
}

_ARCH_KEYS = {
    "amd64": ["amd64", "x86_64", "x86-64"],
    "arm64": ["arm64", "aarch64"],
    "armv7": ["armv7", "armhf"],
    "386":   ["386", "i386", "i686"],
}

# Suffixes and keywords that are never the binary we want
_SKIP_EXT = {".sha256", ".sha512", ".md5", ".sig", ".asc",
             ".sbom", ".pem", ".txt", ".json", ".deb", ".rpm"}
_SKIP_KW  = {"windows", ".exe", "_windows", "-windows",
             "src", "source", ".tar.bz2"}


def _pick_asset(assets: list[str], os_family: str, arch: str) -> str | None:
    """
    Return the best-matching asset URL from a GitHub release.

    Scoring:
      2 — OS match + arch match + archive format (.zip / .tar.gz)
      1 — OS match + arch match (raw binary)

    Falls back to arch-only match for single-platform tools (e.g. assetfinder).
    """
    os_keys   = _OS_KEYS.get(os_family, [os_family])
    arch_keys = _ARCH_KEYS.get(arch, [arch])

    candidates = []
    for url in assets:
        name = url.split("/")[-1].lower()

        if any(name.endswith(e) for e in _SKIP_EXT):
            continue
        if any(k in name for k in _SKIP_KW):
            continue

        has_os   = any(k in name for k in os_keys)
        has_arch = any(k in name for k in arch_keys)

        if has_os and has_arch:
            score = 2 if name.endswith((".zip", ".tar.gz", ".tgz")) else 1
            candidates.append((score, url))

    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    # Fallback: arch-only match (covers tools with a single OS build)
    for url in assets:
        name = url.split("/")[-1].lower()
        if any(name.endswith(e) for e in _SKIP_EXT):
            continue
        if any(k in name for k in _SKIP_KW):
            continue
        if any(k in name for k in arch_keys):
            return url

    return None


# ── GitHub release fetcher ────────────────────────────────────────────────────

def _get_release_assets(repo: str) -> tuple[str, list[str]]:
    """
    Fetch latest release tag + asset download URLs from GitHub API.
    Handles rate-limit (403 / 429) responses explicitly.
    Returns ("unknown", []) on any failure.
    """
    url     = f"https://api.github.com/repos/{repo}/releases/latest"
    headers = {"Accept": "application/vnd.github.v3+json"}

    try:
        if _REQUESTS:
            r = _req.get(url, headers=headers, timeout=10)

            if r.status_code in (403, 429):
                reset = r.headers.get("X-RateLimit-Reset", "")
                print(
                    f"\n    [!] GitHub API rate-limited (HTTP {r.status_code})."
                    f" Resets at Unix time: {reset}"
                    f"\n        Tip: wait a minute and re-run, or add a GitHub token."
                )
                return "unknown", []

            data = r.json()
        else:
            import json
            out  = subprocess.check_output(
                ["curl", "-sf", "-H", f"Accept: {headers['Accept']}", url],
                timeout=15,
            )
            data = json.loads(out)

        # GitHub returns {"message": "...", "documentation_url": "..."} on errors
        if "message" in data and "tag_name" not in data:
            msg = data.get("message", "")
            if "rate limit" in msg.lower():
                print(f"\n    [!] GitHub API rate limited: {msg}")
            return "unknown", []

        tag    = data.get("tag_name", "unknown")
        assets = [a["browser_download_url"] for a in data.get("assets", [])]
        return tag, assets

    except Exception:
        return "unknown", []


# ── Downloader + extractor ────────────────────────────────────────────────────

def _download(url: str, dest: Path, dry_run: bool) -> bool:
    if dry_run:
        print(f"[dry-run] curl -L '{url}' -o {dest}")
        return True
    try:
        if _REQUESTS:
            r = _req.get(url, stream=True, timeout=120)
            r.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in r.iter_content(65536):
                    f.write(chunk)
        else:
            subprocess.run(
                ["curl", "-L", "-o", str(dest), url],
                check=True, capture_output=True, timeout=120,
            )
        return True
    except Exception as e:
        print(f"  [!] Download error: {e}")
        return False


def _extract_binary(archive: Path, binary_name: str,
                    dest_dir: Path, dry_run: bool) -> Path | None:
    if dry_run:
        ext = "unzip" if str(archive).endswith(".zip") else "tar -xzf"
        print(f"[dry-run] {ext} {archive} -C {dest_dir}/")
        return dest_dir / binary_name

    name = archive.name.lower()
    try:
        if name.endswith(".zip"):
            with zipfile.ZipFile(archive) as z:
                z.extractall(dest_dir)
        elif name.endswith((".tar.gz", ".tgz")):
            with tarfile.open(archive, "r:gz") as t:
                t.extractall(dest_dir)
        else:
            # Raw binary — move it into dest_dir
            raw = dest_dir / binary_name
            shutil.copy2(archive, raw)
            return raw
    except Exception as e:
        print(f"  [!] Extraction error: {e}")
        return None

    # Search the extracted tree for the binary
    for candidate in sorted(dest_dir.rglob(binary_name)):
        if candidate.is_file():
            return candidate

    # Fallback: any executable-looking file without an extension
    for candidate in dest_dir.rglob("*"):
        if candidate.is_file() and not candidate.suffix and candidate.stat().st_size > 10_000:
            return candidate

    return None


def download_and_install(tool_name: str, tool_def: dict,
                          os_family: str, arch: str,
                          dry_run: bool) -> tuple[bool, str]:
    repo = tool_def.get("github_repo")
    if not repo:
        return False, "no GitHub repo defined"

    tag, assets = _get_release_assets(repo)
    if not assets:
        return False, f"could not fetch release assets for {repo}"

    asset_url = _pick_asset(assets, os_family, arch)
    if not asset_url:
        sample = [a.split("/")[-1] for a in assets[:6]]
        return False, (
            f"no matching binary for {os_family}/{arch}.\n"
            f"        Available assets: {sample}"
        )

    binary_name = tool_def["binary_name"]
    ver         = tag.lstrip("v")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir   = Path(tmpdir)
        archive  = tmpdir / Path(asset_url).name
        extract  = tmpdir / "extract"
        extract.mkdir()

        if not _download(asset_url, archive, dry_run):
            return False, "download failed"

        bin_path = _extract_binary(archive, binary_name, extract, dry_run)
        if not bin_path:
            return False, "binary not found in archive"

        dest = BIN_DIR / binary_name
        if dry_run:
            print(f"[dry-run] install -m 755 {bin_path} {dest}")
            return True, "dry-run"

        shutil.copy2(bin_path, dest)
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    return True, ver


# ── Package manager install ───────────────────────────────────────────────────

def install_via_pm(pkg: str, pm: str, dry_run: bool) -> tuple[bool, str]:
    cmds = {
        "apt":    ["apt-get", "install", "-y", "-qq", pkg],
        "dnf":    ["dnf",     "install", "-y",        pkg],
        "yum":    ["yum",     "install", "-y",        pkg],
        "pacman": ["pacman",  "-S", "--noconfirm",    pkg],
        "apk":    ["apk",     "add", "--no-cache",    pkg],
        "zypper": ["zypper",  "install", "-y",        pkg],
        "brew":   ["brew",    "install",              pkg],
    }
    cmd = cmds.get(pm)
    if not cmd:
        return False, f"unknown package manager: {pm}"
    if dry_run:
        print(f"[dry-run] {' '.join(cmd)}")
        return True, "dry-run"
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=120)
        return True, "installed"
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode(errors="replace")[:200]


def install_pip_tool(pkg: str, dry_run: bool) -> bool:
    """Install a Python package via pip. Tries --break-system-packages first."""
    if dry_run:
        print(f"[dry-run] {sys.executable} -m pip install --break-system-packages {pkg}")
        return True
    for extra in [["--break-system-packages"], []]:
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet", pkg] + extra,
                check=True, capture_output=True, timeout=120,
            )
            return True
        except subprocess.CalledProcessError:
            continue
    return False


# ── Python deps + symlink ─────────────────────────────────────────────────────

def install_python_deps(dry_run: bool):
    req = BASE_DIR / "requirements.txt"
    if dry_run:
        print(f"[dry-run] {sys.executable} -m pip install --break-system-packages -r {req}")
        return
    for extra in [["--break-system-packages"], []]:
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet",
                 "-r", str(req)] + extra,
                check=True, timeout=120,
            )
            print("  [+] Python dependencies installed")
            return
        except subprocess.CalledProcessError:
            continue
    print("  [!] pip install failed — try: pip install -r requirements.txt")


def create_symlink(dry_run: bool):
    entry = BASE_DIR / "recon_raptor.py"
    link  = BIN_DIR  / "recon_raptor"
    if dry_run:
        print(f"[dry-run] chmod +x {entry}")
        print(f"[dry-run] ln -sf {entry} {link}")
        return
    try:
        entry.chmod(entry.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(entry)
        print(f"  [+] Symlink: {link} → {entry}")
    except Exception as e:
        print(f"  [!] Could not create symlink: {e}")
        print(f"      Run manually: sudo ln -sf {entry} {link}")


# ── Main entrypoint ───────────────────────────────────────────────────────────

def run_install(args):
    dry_run     = getattr(args, "dry_run",      False)
    install_all = getattr(args, "install_all",  False)
    exclude_raw = getattr(args, "exclude",      "") or ""
    excluded    = {e.strip() for e in exclude_raw.split(",") if e.strip()}

    if not dry_run:
        require_sudo()

    check_connectivity(dry_run)

    os_family, pkg_mgr = detect_os()
    arch                = get_arch()
    real_user, _        = get_real_user()

    tag = "[dry-run]" if dry_run else "[*]"
    print(f"\n{tag} System: {os_family}  ·  {arch}  ·  package manager: {pkg_mgr or 'none'}")
    if not dry_run:
        print(f"[*] Running as root (original user: {real_user})\n")
    else:
        print()

    # Update package index
    if pkg_mgr == "apt":
        if dry_run:
            print("[dry-run] apt-get update -qq")
        else:
            subprocess.run(["apt-get", "update", "-qq"],
                           check=False, capture_output=True)
    elif pkg_mgr in ("dnf", "yum") and not dry_run:
        subprocess.run([pkg_mgr, "makecache", "-q"],
                       check=False, capture_output=True)

    # Python deps first
    print("[*] Installing Python dependencies...")
    install_python_deps(dry_run)
    print()

    for tool_name, tool_def in TOOLS.items():

        # ── Skip logic ───────────────────────────────────────────────────────
        if tool_name in excluded:
            print(f"  [-] {tool_name:<16} skipped (excluded)")
            continue

        if tool_def.get("optional") and not install_all:
            continue

        if shutil.which(tool_name):
            print(f"  [✓] {tool_name:<16} already installed")
            continue

        print(f"  [>] {tool_name:<16} {tool_def['description']}")

        # ── pip tools ────────────────────────────────────────────────────────
        if "pip" in tool_def:
            ok = install_pip_tool(tool_def["pip"], dry_run)
            if ok:
                print(f"      [+] pip install: {tool_def['pip']}")
            else:
                print(f"      [!] pip failed. Try manually: pip install {tool_def['pip']}")
            continue

        # ── package manager ──────────────────────────────────────────────────
        pm_pkg = tool_def.get(pkg_mgr) if pkg_mgr else None
        if pm_pkg:
            ok, msg = install_via_pm(pm_pkg, pkg_mgr, dry_run)
            if ok:
                print(f"      [+] installed via {pkg_mgr}")
                time.sleep(0.3)
                continue
            print(f"      [!] {pkg_mgr} failed ({msg[:80]}), trying GitHub...")

        # ── GitHub binary ────────────────────────────────────────────────────
        if "github_repo" in tool_def:
            ok, msg = download_and_install(
                tool_name, tool_def, os_family, arch, dry_run
            )
            if ok:
                print(f"      [+] installed from GitHub ({msg})")
            else:
                print(f"      [!] GitHub install failed: {msg}")
            # Small delay between GitHub API calls to avoid rate limiting
            time.sleep(0.8)
            continue

        print(f"      [!] No install method for {os_family}")

    # Symlink
    print("\n[*] Setting up recon_raptor command...")
    create_symlink(dry_run)

    if dry_run:
        print("\n[i] Dry run complete — nothing was installed.")
        print("    Run the commands above, then verify with: recon_raptor check")
    else:
        print(f"\n[+] Installation complete.")
        print(f"    Open a new terminal, then run: recon_raptor check")

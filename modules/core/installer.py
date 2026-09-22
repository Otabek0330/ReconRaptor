"""
modules/core/installer.py  v3.0

Install flow (per tool):
  1. Already installed?      → skip
  2. pip tool (dirsearch)?   → pipx → pip → git-clone fallback
  3. go install?             → GOBIN=/usr/local/bin go install pkg@ver
  4. Package manager?        → apt / dnf / pacman / brew (not brew-as-root)
  5. GitHub binary?          → OS-correct asset, SHA-256 verified (fail-closed)
  6. Build from source?      → massdns (C program)

Security / robustness fixes in v3.0
───────────────────────────────────
#28 SHA-256 verification is fail-CLOSED and real
    - Verifies against per-asset .sha256 sidecars AND `*_checksums.txt`
      files (which ProjectDiscovery ships and the old code skipped).
    - A hash MISMATCH aborts the install; a verification ERROR no longer
      returns "verified". When no checksum is published at all it installs
      but says clearly it could NOT verify — it never claims verification
      that didn't happen.
    - The Go tarball is now verified against the sha256 published in
      go.dev's release JSON.

#29 GOSUMDB stays ON by default
    Go's checksum-DB protection is only disabled if you explicitly set
    RR_GO_NOSUMDB=1 (for proxied/air-gapped networks), with a warning.

#30 No tar-slip / zip-slip as root
    Archives are extracted with tarfile's data filter (3.12+) or, on older
    Python, with explicit path-traversal validation of every member.

#31 Atomic Go (re)install
    Go is staged in a temp dir and swapped in only after a successful
    extract, so a failed download/extract can't leave the box with no Go.

#32 No fixed /tmp build path
    massdns builds in a mkdtemp() dir, not a predictable /tmp/massdns_build
    (which was a symlink-race target under root).

#33 go install runs before the package manager
    Matches the documented "go install is primary" design (apt's gobuster
    was winning before). brew is never run as root (it refuses); on macOS
    root, brew steps are skipped in favour of go install / source.

#35 Version pinning is supported
    Each tool can carry a `pin`; set RR_INSTALL_LATEST=1 to force @latest.
    Pins are left unset here (can't be validated offline) — fill them in to
    stop a tool's flag rename from silently breaking the parsers.

#36 No crash on a slow package manager
    Every subprocess call is timeout-guarded and exception-safe.

#37 Asset picker requires an OS match
    The old arch-only fallback could pick a Darwin binary on Linux; the
    picker now always requires the target OS (and treats an arch-less asset
    name as amd64).
"""

import os, re, sys, shutil, platform, subprocess
import tempfile, zipfile, tarfile, stat, time, hashlib, json
from pathlib import Path

try:
    import requests as _req
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

BASE_DIR = Path(__file__).parent.parent.parent
BIN_DIR  = Path("/usr/local/bin")

GO_MIN_VERSION     = (1, 21)
GO_LATEST_FALLBACK = "1.24.3"
GO_ARCH_MAP = {"amd64": "amd64", "arm64": "arm64", "armv7": "armv6l", "386": "386"}

# RR_INSTALL_LATEST=1 forces @latest even where a pin is set.
_USE_LATEST = os.environ.get("RR_INSTALL_LATEST", "").lower() not in ("", "0", "false", "no")
# RR_GO_NOSUMDB=1 disables Go's checksum DB (for proxied/firewalled networks).
_NOSUMDB    = os.environ.get("RR_GO_NOSUMDB", "").lower() not in ("", "0", "false", "no")

TOOLS = {
    "subfinder": {
        "required": True,  "optional": False,
        "description": "passive subdomain enumeration",
        "go_install":  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "github_repo": "projectdiscovery/subfinder", "binary_name": "subfinder",
        "apt": None, "brew": "subfinder", "pin": None,
    },
    "assetfinder": {
        "required": True,  "optional": False,
        "description": "passive subdomain enumeration",
        "go_install":  "github.com/tomnomnom/assetfinder@latest",
        "github_repo": "tomnomnom/assetfinder", "binary_name": "assetfinder",
        "apt": None, "brew": None, "pin": None,
    },
    "findomain": {
        "required": False, "optional": False,
        "description": "passive subdomain enumeration",
        "go_install":  None,
        "github_repo": "findomain/findomain", "binary_name": "findomain",
        "apt": None, "brew": "findomain", "pin": None,
    },
    "puredns": {
        "required": True,  "optional": False,
        "description": "DNS bruteforce + wildcard filter",
        "go_install":  "github.com/d3mondev/puredns/v2@latest",
        "github_repo": "d3mondev/puredns", "binary_name": "puredns",
        "apt": None, "brew": None, "pin": None,
    },
    "massdns": {
        "required": True,  "optional": False,
        "description": "puredns resolver backend (C program)",
        "go_install":  None, "build_from_source": True,
        "github_repo": "blechschmidt/massdns", "binary_name": "massdns",
        "apt": "massdns", "brew": "massdns", "pin": None,
    },
    "dnsx": {
        "required": True,  "optional": False,
        "description": "multi-record DNS resolution",
        "go_install":  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "github_repo": "projectdiscovery/dnsx", "binary_name": "dnsx",
        "apt": None, "brew": "dnsx", "pin": None,
    },
    "httpx": {
        "required": True,  "optional": False,
        "description": "HTTP probing + fingerprinting",
        "go_install":  "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "github_repo": "projectdiscovery/httpx", "binary_name": "httpx",
        "apt": None, "brew": "httpx", "pin": None,
    },
    "naabu": {
        "required": False, "optional": False,
        "description": "fast port scanner",
        "go_install":  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "github_repo": "projectdiscovery/naabu", "binary_name": "naabu",
        "apt": None, "brew": "naabu", "pin": None,
    },
    "gobuster": {
        "required": True,  "optional": False,
        "description": "directory bruteforce",
        "go_install":  "github.com/OJ/gobuster/v3@latest",
        "github_repo": "OJ/gobuster", "binary_name": "gobuster",
        "apt": "gobuster", "brew": "gobuster", "pin": None,
    },
    "dirsearch": {
        "required": False, "optional": False,
        "description": "recursive web path scanner",
        "pip": "dirsearch",
        "git_clone": "https://github.com/maurosoria/dirsearch.git",
        "binary_name": "dirsearch",
    },
    "ffuf": {
        "required": False, "optional": False,
        "description": "web fuzzer",
        "go_install":  "github.com/ffuf/ffuf/v2@latest",
        "github_repo": "ffuf/ffuf", "binary_name": "ffuf",
        "apt": None, "brew": "ffuf", "pin": None,
    },
    "gowitness": {
        "required": False, "optional": True,
        "description": "screenshot capture",
        "go_install":  "github.com/sensepost/gowitness@latest",
        "github_repo": "sensepost/gowitness", "binary_name": "gowitness",
        "apt": None, "brew": None, "pin": None,
    },
    "gau": {
        "required": False, "optional": True,
        "description": "wayback URL harvesting",
        "go_install":  "github.com/lc/gau/v2/cmd/gau@latest",
        "github_repo": "lc/gau", "binary_name": "gau",
        "apt": None, "brew": "gau", "pin": None,
    },
    "nuclei": {
        "required": False, "optional": True,
        "description": "template-based vuln scanning",
        "go_install":  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "github_repo": "projectdiscovery/nuclei", "binary_name": "nuclei",
        "apt": None, "brew": "nuclei", "pin": None,
    },
}

_OS_KEYS   = {"linux": ["linux"], "macos": ["darwin", "macos", "mac", "osx"]}
_ARCH_KEYS = {"amd64": ["amd64", "x86_64"], "arm64": ["arm64", "aarch64"],
              "armv7": ["armv7"], "386": ["386", "i386"]}
_ALL_ARCH_TOKENS = {t for toks in _ARCH_KEYS.values() for t in toks}
_SKIP_EXT  = {".sha256", ".sha512", ".md5", ".sig", ".asc", ".sbom",
              ".pem", ".txt", ".json", ".deb", ".rpm"}
_SKIP_KW   = {"windows", ".exe", "_windows", "-windows", "src", "source"}


# ── Safe subprocess helpers (finding #36) ─────────────────────────────────────

def _run_safe(cmd, timeout=120):
    """Run a command; never raise. Returns (ok, combined_output)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.returncode == 0), (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return False, f"[timeout after {timeout}s: {cmd[0]}]"
    except FileNotFoundError:
        return False, f"[not found: {cmd[0]}]"
    except Exception as exc:
        return False, f"[error: {exc}]"


def _run_local(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except Exception as exc:
        return "", str(exc), -1


# ── Sudo enforcement ──────────────────────────────────────────────────────────

def require_sudo():
    if os.geteuid() != 0:
        github_token = os.environ.get("GITHUB_TOKEN", "")
        sudo_path = shutil.which("sudo")
        if sudo_path:
            print("[*] Re-launching with 'sudo -E' to preserve your environment")
            if github_token:
                print("    (GITHUB_TOKEN detected — will be carried through)")
            print()
            try:
                os.execvp(sudo_path, [sudo_path, "-E", sys.executable] + sys.argv)
            except Exception:
                pass
        print("""
[!]  recon_raptor install requires root privileges.

     Run with sudo:
       sudo -E recon_raptor install --all

     The -E flag matters if you've set GITHUB_TOKEN — plain 'sudo'
     strips exported environment variables by default.

     No sudo? Preview every command with:
       recon_raptor install --dry-run
""")
        sys.exit(1)


def get_real_user():
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        try:
            pw = pwd.getpwnam(sudo_user)
            return pw.pw_name, Path(pw.pw_dir)
        except KeyError:
            pass
    return "root", Path("/root")


# ── OS / arch ─────────────────────────────────────────────────────────────────

def detect_os():
    system = platform.system()
    if system == "Darwin":
        return "macos", ("brew" if shutil.which("brew") else None)
    if system == "Linux":
        try:
            if "microsoft" in Path("/proc/version").read_text().lower():
                print("[i] WSL detected — treating as Linux")
        except OSError:
            pass
        try:
            rel = Path("/etc/os-release").read_text().lower()
        except OSError:
            return "linux", _fallback_pm()
        if any(d in rel for d in ["ubuntu", "debian", "kali", "parrot", "mint", "pop"]):
            return "debian", "apt"
        if any(d in rel for d in ["fedora", "rhel", "rocky", "alma", "centos", "red hat"]):
            return "rhel", ("dnf" if shutil.which("dnf") else "yum")
        if any(d in rel for d in ["arch", "manjaro", "blackarch", "garuda"]):
            return "arch", "pacman"
        if "alpine" in rel:   return "alpine", "apk"
        if "opensuse" in rel: return "suse", "zypper"
        return "linux", _fallback_pm()
    return "unknown", None


def _fallback_pm():
    for pm in ["apt", "dnf", "yum", "pacman", "apk", "zypper", "brew"]:
        if shutil.which(pm):
            return pm
    return None


def get_arch():
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64",
            "armv7l": "armv7", "i686": "386", "i386": "386"}.get(platform.machine(), "amd64")


def check_connectivity(dry_run=False):
    if dry_run:
        print("[dry-run] connectivity check → https://go.dev")
        return
    try:
        if _REQUESTS:
            _req.get("https://go.dev", timeout=5)
        else:
            ok, _ = _run_safe(["curl", "-s", "--head", "https://go.dev", "--max-time", "5"], 8)
            if not ok:
                raise RuntimeError("curl failed")
    except Exception:
        print("[!] No internet connection.")
        sys.exit(1)


# ── Small HTTP helpers ────────────────────────────────────────────────────────

def _http_json(url, timeout=15):
    try:
        if _REQUESTS:
            r = _req.get(url, timeout=timeout)
            r.raise_for_status()
            return r.json()
        import urllib.request
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _http_text(url, timeout=15):
    try:
        if _REQUESTS:
            r = _req.get(url, timeout=timeout)
            r.raise_for_status()
            return r.text
        import urllib.request
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode(errors="replace")
    except Exception:
        return ""


# ── SHA-256 verification (finding #28) ────────────────────────────────────────

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def _lookup_checksum(text: str, filename: str):
    """Find 'filename' in a checksums.txt body; return its hex hash or None."""
    fn = filename.lower()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].lstrip("*").lower().endswith(fn):
            return parts[0].strip().lower()
        if len(parts) == 1 and len(parts[0]) in (64,):  # bare hash
            return parts[0].strip().lower()
    return None


def _safe_extract_tar(tf: tarfile.TarFile, dest: Path):
    """Extract a tar safely (no path traversal / absolute paths)."""
    try:
        tf.extractall(dest, filter="data")   # Python 3.12+
        return
    except TypeError:
        pass
    dest_real = os.path.realpath(dest)
    for m in tf.getmembers():
        target = os.path.realpath(os.path.join(dest, m.name))
        if not (target == dest_real or target.startswith(dest_real + os.sep)):
            raise RuntimeError(f"unsafe tar member: {m.name}")
        if (m.issym() or m.islnk()):
            link = os.path.realpath(os.path.join(os.path.dirname(target), m.linkname))
            if not (link == dest_real or link.startswith(dest_real + os.sep)):
                raise RuntimeError(f"unsafe tar link: {m.name} -> {m.linkname}")
    tf.extractall(dest)


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path):
    dest_real = os.path.realpath(dest)
    for name in zf.namelist():
        target = os.path.realpath(os.path.join(dest, name))
        if not (target == dest_real or target.startswith(dest_real + os.sep)):
            raise RuntimeError(f"unsafe zip member: {name}")
    zf.extractall(dest)


# ── Go detection / installation ───────────────────────────────────────────────

def _go_bin() -> str:
    for c in [shutil.which("go"), "/usr/local/go/bin/go"]:
        if c and Path(c).exists():
            return c
    return "go"


def _go_version():
    try:
        r = subprocess.run([_go_bin(), "version"], capture_output=True, text=True, timeout=5)
        m = re.search(r'go(\d+)\.(\d+)', r.stdout)
        return (int(m.group(1)), int(m.group(2))) if m else None
    except Exception:
        return None


def _needs_go() -> bool:
    v = _go_version()
    return v is None or v < GO_MIN_VERSION


def _get_go_latest() -> str:
    txt = _http_text("https://go.dev/VERSION?m=text", timeout=10)
    if txt:
        return txt.strip().split('\n')[0].lstrip('go')
    return GO_LATEST_FALLBACK


def _go_sha256(fname: str):
    """Return the official sha256 for a Go archive filename, or None."""
    data = _http_json("https://go.dev/dl/?mode=json&include=all", timeout=15)
    if not isinstance(data, list):
        return None
    for entry in data:
        for f in entry.get("files", []):
            if f.get("filename") == fname and f.get("sha256"):
                return f["sha256"].lower()
    return None


def _go_env(dry_run: bool = False) -> dict:
    env = os.environ.copy()
    if os.geteuid() == 0:
        gopath, gocache = Path("/root/go"), Path("/root/.cache/go-build")
    else:
        gopath, gocache = Path.home() / "go", Path.home() / ".cache" / "go-build"

    if not dry_run:
        for d in [gopath / "src", gopath / "bin", gopath / "pkg", gocache]:
            d.mkdir(parents=True, exist_ok=True)

    env["GOPATH"]  = str(gopath)
    env["GOCACHE"] = str(gocache)
    env["GOBIN"]   = str(BIN_DIR)
    # GOFLAGS=-mod=mod is intentionally NOT set — it breaks `go install pkg@ver`.
    if _NOSUMDB:
        env["GOSUMDB"] = "off"   # opt-in only (finding #29)
    go_bindir = str(Path(_go_bin()).parent)
    if go_bindir not in env.get("PATH", ""):
        env["PATH"] = go_bindir + ":" + env.get("PATH", "")
    if "/usr/local/go/bin" not in env.get("PATH", ""):
        env["PATH"] = "/usr/local/go/bin:" + env.get("PATH", "")
    return env


def _ensure_build_deps(pkg_mgr: str, dry_run: bool):
    if shutil.which("git"):
        return
    print("  [i] git not found — installing (required for go install) ...")
    if pkg_mgr:
        install_via_pm("git", pkg_mgr, dry_run)
    else:
        print("  [!] Cannot auto-install git — install it manually then re-run")


def _test_go_install(dry_run: bool) -> bool:
    if dry_run:
        return True
    ok, _ = _run_safe([_go_bin(), "env", "GOPATH", "GOBIN"], 10)
    return ok


def install_go(os_family: str, arch: str, dry_run: bool) -> bool:
    go_os   = "darwin" if os_family == "macos" else "linux"
    go_arch = GO_ARCH_MAP.get(arch, "amd64")
    ver     = _get_go_latest()
    fname   = f"go{ver}.{go_os}-{go_arch}.tar.gz"
    url     = f"https://go.dev/dl/{fname}"

    print(f"\n[*] Installing Go {ver} ({go_os}/{go_arch}) from go.dev ...")

    if dry_run:
        print(f"[dry-run] curl -L {url} -o /tmp/{fname}")
        print("[dry-run] verify sha256 against go.dev release JSON")
        print("[dry-run] atomically swap into /usr/local/go")
        return True

    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / fname
        if not _download_raw(url, archive):
            print("    [!] Go download failed — install manually: https://go.dev/doc/install")
            return False

        # Verify tarball (finding #28). Mismatch aborts; unknown → warn.
        expected = _go_sha256(fname)
        if expected:
            actual = _sha256_file(archive)
            if actual != expected:
                print("    [!] Go tarball SHA-256 MISMATCH — refusing to install")
                return False
            print("    [+] Go tarball SHA-256 verified ✓")
        else:
            print("    [i] Could not fetch Go checksum — proceeding UNVERIFIED")

        # Atomic swap (finding #31): stage, then replace only on success.
        try:
            stage_parent = Path(tempfile.mkdtemp(dir="/usr/local", prefix=".go-stage-"))
        except Exception:
            stage_parent = Path(tempfile.mkdtemp(prefix="go-stage-"))
        try:
            with tarfile.open(archive, "r:gz") as tf:
                _safe_extract_tar(tf, stage_parent)
            staged = stage_parent / "go"
            if not (staged / "bin" / "go").exists():
                print("    [!] Extracted Go looks incomplete — aborting")
                return False

            go_dir = Path("/usr/local/go")
            backup = Path("/usr/local/go.old")
            if go_dir.exists():
                if backup.exists():
                    shutil.rmtree(backup, ignore_errors=True)
                go_dir.rename(backup)
            try:
                shutil.move(str(staged), str(go_dir))
            except Exception:
                if backup.exists() and not go_dir.exists():
                    backup.rename(go_dir)   # restore
                raise
            shutil.rmtree(backup, ignore_errors=True)
        except Exception as exc:
            print(f"    [!] Go install failed: {exc}")
            return False
        finally:
            shutil.rmtree(stage_parent, ignore_errors=True)

    go_bin_dir = "/usr/local/go/bin"
    if go_bin_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = go_bin_dir + ":" + os.environ.get("PATH", "")
    try:
        Path("/etc/profile.d/golang.sh").write_text(
            "#!/bin/sh\nexport PATH=$PATH:/usr/local/go/bin\nexport GOPATH=$HOME/go\n")
    except Exception:
        pass

    ver_check = _go_version()
    if ver_check:
        print(f"    [+] Go {ver_check[0]}.{ver_check[1]} installed ✓")
        return True
    print("    [!] Go installed but not detected — check PATH after install")
    return False


# ── go install ────────────────────────────────────────────────────────────────

def _go_pkg_ref(tool_def: dict) -> str:
    pkg = tool_def["go_install"]
    pin = tool_def.get("pin")
    if pin and not _USE_LATEST:
        return pkg.rsplit("@", 1)[0] + "@" + pin
    return pkg


def install_via_go(pkg: str, binary_name: str, dry_run: bool):
    go = _go_bin()
    if dry_run:
        env = _go_env(dry_run=True)
        print(f"[dry-run] GOPATH={env['GOPATH']} GOBIN={BIN_DIR} {go} install {pkg}")
        return True, "dry-run"

    if not shutil.which("go") and not Path("/usr/local/go/bin/go").exists():
        return False, "go not found — run: sudo recon_raptor install first"

    env = _go_env()
    try:
        result = subprocess.run([go, "install", pkg], env=env,
                                capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            combined = ((result.stderr or "") or (result.stdout or "")).strip()
            error_lines = [l for l in combined.splitlines()
                           if l.strip() and not l.startswith('#')
                           and "go: downloading" not in l]
            return False, ('\n'.join(error_lines[-5:]) if error_lines else combined[:300])

        dest = BIN_DIR / binary_name
        if dest.exists() and dest.stat().st_size > 0:
            dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            return True, "go install"

        gopath_bin = Path(env["GOPATH"]) / "bin" / binary_name
        if gopath_bin.exists() and gopath_bin.stat().st_size > 0:
            shutil.copy2(gopath_bin, dest)
            dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            return True, f"go install (recovered from {gopath_bin})"

        return False, (f"go install exited 0 but binary not found at {dest} "
                       f"or {gopath_bin} — verify: GOBIN={BIN_DIR} go install {pkg}")
    except subprocess.TimeoutExpired:
        return False, "timed out after 5 min — check network / proxy settings"
    except Exception as exc:
        return False, str(exc)


# ── pip / dirsearch ───────────────────────────────────────────────────────────

def install_pip_tool(pkg: str, dry_run: bool) -> bool:
    if dry_run:
        print(f"[dry-run] pipx install {pkg}  (fallback: pip install --break-system-packages {pkg})")
        return True
    if shutil.which("pipx"):
        ok, _ = _run_safe(["pipx", "install", pkg], 180)
        if ok:
            return True
    for extra in [["--break-system-packages"], ["--user"], []]:
        ok, _ = _run_safe([sys.executable, "-m", "pip", "install", "--quiet", pkg] + extra, 180)
        if ok:
            return True
    return False


def install_dirsearch_git(dry_run: bool) -> bool:
    install_dir = Path("/opt/dirsearch")
    repo_url    = "https://github.com/maurosoria/dirsearch.git"
    if dry_run:
        print(f"[dry-run] git clone --depth=1 {repo_url} {install_dir}")
        print(f"[dry-run] pip install -r {install_dir}/requirements.txt")
        print(f"[dry-run] # create wrapper at {BIN_DIR}/dirsearch")
        return True
    if install_dir.exists():
        shutil.rmtree(install_dir)
    _, _, rc = _run_local(["git", "clone", "--depth=1", repo_url, str(install_dir)], 180)
    if rc != 0:
        return False
    req = install_dir / "requirements.txt"
    if req.exists():
        for extra in [["--break-system-packages"], []]:
            ok, _ = _run_safe([sys.executable, "-m", "pip", "install", "--quiet",
                               "-r", str(req)] + extra, 180)
            if ok:
                break
    main = install_dir / "dirsearch.py"
    if not main.exists():
        main = next(install_dir.glob("*.py"), None)
    if not main:
        return False
    main.chmod(main.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    wrapper = BIN_DIR / "dirsearch"
    wrapper.write_text(f"#!/usr/bin/env bash\nexec {sys.executable} {main} \"$@\"\n")
    wrapper.chmod(0o755)
    return True


# ── Package manager ───────────────────────────────────────────────────────────

def install_via_pm(pkg: str, pm: str, dry_run: bool):
    # brew refuses to run as root; skip it under sudo (finding #33).
    if pm == "brew" and os.geteuid() == 0 and not dry_run:
        return False, "brew cannot run as root — using go install / source instead"

    cmds = {
        "apt":    ["apt-get", "install", "-y", "-qq", pkg],
        "dnf":    ["dnf", "install", "-y", pkg],
        "yum":    ["yum", "install", "-y", pkg],
        "pacman": ["pacman", "-S", "--noconfirm", pkg],
        "apk":    ["apk", "add", "--no-cache", pkg],
        "zypper": ["zypper", "install", "-y", pkg],
        "brew":   ["brew", "install", pkg],
    }
    cmd = cmds.get(pm)
    if not cmd:
        return False, f"unknown PM: {pm}"
    if dry_run:
        print(f"[dry-run] {' '.join(cmd)}")
        return True, "dry-run"
    ok, out = _run_safe(cmd, 300)
    return (True, "installed") if ok else (False, out[:200])


# ── massdns from source (finding #32: mkdtemp) ────────────────────────────────

def build_massdns_from_source(dry_run: bool) -> bool:
    repo = "https://github.com/blechschmidt/massdns.git"
    if dry_run:
        print(f"[dry-run] git clone --depth=1 {repo} <tmpdir>")
        print("[dry-run] make -C <tmpdir>")
        print(f"[dry-run] install -m 755 <tmpdir>/bin/massdns {BIN_DIR}/massdns")
        return True
    build_dir = Path(tempfile.mkdtemp(prefix="rr_massdns_"))
    try:
        for cmd, tmo in [(["git", "clone", "--depth=1", repo, str(build_dir)], 120),
                         (["make", "-C", str(build_dir)], 180)]:
            _, stderr, rc = _run_local(cmd, tmo)
            if rc != 0:
                print(f"      [!] {cmd[0]} failed: {stderr[:120]}")
                return False
        built = next((p for p in [build_dir / "bin" / "massdns", build_dir / "massdns"]
                      if p.exists()), None)
        if not built:
            return False
        dest = BIN_DIR / "massdns"
        shutil.copy2(built, dest)
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return True
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)


# ── GitHub binary download ────────────────────────────────────────────────────

def _github_headers():
    hdrs = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    return hdrs


def _get_release_assets(repo: str):
    """Return (tag, asset_urls, sha256_sidecar_map, checksums_txt_url)."""
    url  = f"https://api.github.com/repos/{repo}/releases/latest"
    hdrs = _github_headers()
    try:
        if _REQUESTS:
            r = _req.get(url, headers=hdrs, timeout=15)
            if r.status_code in (403, 429):
                print(f"\n    [!] GitHub API rate limited (remaining: "
                      f"{r.headers.get('X-RateLimit-Remaining','0')}, "
                      f"resets: {r.headers.get('X-RateLimit-Reset','?')})")
                print("        Fix: export GITHUB_TOKEN=your_token  (free, no scopes)")
                return "unknown", [], {}, None
            data = r.json()
        else:
            import urllib.request
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
        if "message" in data and "tag_name" not in data:
            return "unknown", [], {}, None
        tag     = data.get("tag_name", "unknown")
        assets  = [a["browser_download_url"] for a in data.get("assets", [])]
        sha_map = {a["name"].replace(".sha256", ""): a["browser_download_url"]
                   for a in data.get("assets", []) if a["name"].endswith(".sha256")}
        checksums_url = next(
            (a["browser_download_url"] for a in data.get("assets", [])
             if "checksum" in a["name"].lower()), None)
        return tag, assets, sha_map, checksums_url
    except Exception:
        return "unknown", [], {}, None


def _pick_asset(assets, os_family, arch):
    """Pick the best asset — ALWAYS requiring an OS match (finding #37)."""
    os_keys   = _OS_KEYS.get(os_family, [os_family])
    arch_keys = _ARCH_KEYS.get(arch, [arch])

    def score(name):
        if any(name.endswith(e) for e in _SKIP_EXT):
            return None
        if any(k in name for k in _SKIP_KW):
            return None
        if not any(k in name for k in os_keys):
            return None                      # OS match is mandatory
        has_arch     = any(k in name for k in arch_keys)
        has_any_arch = any(k in name for k in _ALL_ARCH_TOKENS)
        # Accept an arch-less asset only when target is amd64 (common default).
        if not has_arch and not (arch == "amd64" and not has_any_arch):
            return None
        s = 2 if name.endswith((".zip", ".tar.gz", ".tgz")) else 1
        if has_arch:
            s += 1
        return s

    candidates = []
    for url in assets:
        s = score(url.split("/")[-1].lower())
        if s:
            candidates.append((s, url))
    if candidates:
        candidates.sort(reverse=True)
        return candidates[0][1]
    return None


def _download_raw(url: str, dest: Path) -> bool:
    try:
        if _REQUESTS:
            r = _req.get(url, stream=True, timeout=180)
            r.raise_for_status()
            total = int(r.headers.get("content-length", 0))
            received = 0
            with open(dest, "wb") as f:
                for chunk in r.iter_content(65536):
                    f.write(chunk)
                    received += len(chunk)
                    if total:
                        pct = received / total * 100
                        print(f"\r        {received/1_048_576:5.1f} MB / "
                              f"{total/1_048_576:.1f} MB  ({pct:.0f}%)", end="", flush=True)
            if total:
                print()
        else:
            ok, out = _run_safe(["curl", "-L", "-o", str(dest), url], 180)
            if not ok:
                raise RuntimeError(out)
        return True
    except Exception as exc:
        print(f"\n      [!] Download error: {exc}")
        return False


def _extract_binary(archive: Path, binary_name: str, dest_dir: Path, dry_run: bool):
    if dry_run:
        ext = "unzip" if str(archive).endswith(".zip") else "tar -xzf"
        print(f"[dry-run] {ext} {archive} -C {dest_dir}/")
        return dest_dir / binary_name
    name = archive.name.lower()
    try:
        if name.endswith(".zip"):
            with zipfile.ZipFile(archive) as z:
                _safe_extract_zip(z, dest_dir)
        elif name.endswith((".tar.gz", ".tgz")):
            with tarfile.open(archive, "r:gz") as t:
                _safe_extract_tar(t, dest_dir)
        else:
            raw = dest_dir / binary_name
            shutil.copy2(archive, raw)
            return raw
    except Exception as exc:
        print(f"      [!] Extraction error: {exc}")
        return None
    for c in sorted(dest_dir.rglob(binary_name)):
        if c.is_file():
            return c
    for c in dest_dir.rglob("*"):
        if c.is_file() and not c.suffix and c.stat().st_size > 10_000:
            return c
    return None


def download_and_install(tool_name, tool_def, os_family, arch, dry_run):
    repo = tool_def.get("github_repo")
    if not repo:
        return False, "no GitHub repo"
    tag, assets, sha_map, checksums_url = _get_release_assets(repo)
    if not assets:
        return False, "no release assets (GitHub rate limit or no releases)"
    asset_url = _pick_asset(assets, os_family, arch)
    if not asset_url:
        return False, f"no {os_family}/{arch} binary. Assets: {[a.split('/')[-1] for a in assets[:5]]}"
    binary_name = tool_def["binary_name"]
    asset_name  = Path(asset_url).name

    with tempfile.TemporaryDirectory() as td:
        td      = Path(td)
        archive = td / asset_name
        extract = td / "extract"
        extract.mkdir()
        if dry_run:
            print(f"[dry-run] download {asset_url}")
            print(f"[dry-run] verify sha256, extract, install -m 755 → {BIN_DIR/binary_name}")
            return True, "dry-run"
        if not _download_raw(asset_url, archive):
            return False, "download failed"

        # Verify (finding #28): sidecar first, then checksums.txt. Fail-closed.
        expected = None
        if asset_name in sha_map:
            expected = (_http_text(sha_map[asset_name]).split() or [""])[0].lower() or None
        if not expected and checksums_url:
            expected = _lookup_checksum(_http_text(checksums_url), asset_name)
        if expected:
            if _sha256_file(archive) != expected:
                return False, "SHA-256 MISMATCH — refusing to install"
        else:
            print("      [i] no published checksum for this asset — installing UNVERIFIED")

        bin_path = _extract_binary(archive, binary_name, extract, dry_run)
        if not bin_path:
            return False, "binary not found in archive"
        dest = BIN_DIR / binary_name
        shutil.copy2(bin_path, dest)
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    suffix = "" if expected else " (unverified)"
    return True, tag.lstrip("v") + suffix


# ── Python deps + symlink ─────────────────────────────────────────────────────

def install_python_deps(dry_run: bool):
    req = BASE_DIR / "requirements.txt"
    if dry_run:
        print(f"[dry-run] pip install --break-system-packages -r {req}")
        return
    for extra in [["--break-system-packages"], []]:
        ok, _ = _run_safe([sys.executable, "-m", "pip", "install", "--quiet",
                           "-r", str(req)] + extra, 180)
        if ok:
            print("  [+] Python dependencies installed")
            return
    print("  [!] pip install failed — try: pip install -r requirements.txt")


def create_symlink(dry_run: bool):
    entry = BASE_DIR / "recon_raptor.py"
    link  = BIN_DIR / "recon_raptor"
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
    except Exception as exc:
        print(f"  [!] Symlink failed: {exc}")


# ── Main entrypoint ───────────────────────────────────────────────────────────

def run_install(args):
    dry_run     = getattr(args, "dry_run",     False)
    install_all = getattr(args, "install_all", False)
    excluded    = {e.strip() for e in (getattr(args, "exclude", "") or "").split(",") if e.strip()}

    if not dry_run:
        require_sudo()

    check_connectivity(dry_run)
    os_family, pkg_mgr = detect_os()
    arch = get_arch()
    real_user, _ = get_real_user()

    github_token = os.environ.get("GITHUB_TOKEN", "")
    tag = "[dry-run]" if dry_run else "[*]"
    print(f"\n{tag} System: {os_family}  ·  {arch}  ·  pkg manager: {pkg_mgr or 'none'}")

    if _NOSUMDB:
        print("[!] RR_GO_NOSUMDB set — Go checksum DB verification DISABLED for this run")
    if _USE_LATEST:
        print("[i] RR_INSTALL_LATEST set — using @latest for all Go tools")

    if github_token:
        print("[*] GITHUB_TOKEN set — 5000 GitHub API req/hr ✓")
    else:
        sudo_user = os.environ.get("SUDO_USER", "")
        if sudo_user and not dry_run:
            print("[i] No GITHUB_TOKEN visible — if you exported it, use 'sudo -E' or")
            print("    sudo GITHUB_TOKEN=your_token python3 recon_raptor.py install --all")
            print("    (Only affects the GitHub binary fallback; go install works either way.)")
        else:
            print("[i] No GITHUB_TOKEN — anonymous GitHub API (60 req/hr limit)")
            print("    Free token (no scopes): https://github.com/settings/tokens/new")

    if os_family == "macos" and os.geteuid() == 0 and pkg_mgr == "brew":
        print("[i] macOS as root — brew is disabled (it refuses root); using go install / source")

    print(f"\n{tag} Running as root (original user: {real_user})\n" if not dry_run else "")

    # ── Step 0: package index ─────────────────────────────────────────────────
    if pkg_mgr == "apt":
        if dry_run:
            print("[dry-run] apt-get update -qq")
        else:
            _run_safe(["apt-get", "update", "-qq"], 180)
    elif pkg_mgr in ("dnf", "yum") and not dry_run:
        _run_safe([pkg_mgr, "makecache", "-q"], 180)

    # ── Step 1: Python deps ───────────────────────────────────────────────────
    print("[*] Installing Python dependencies ...")
    install_python_deps(dry_run)
    print()

    # ── Step 2: Go ────────────────────────────────────────────────────────────
    go_available = False
    if _needs_go():
        print("[*] Go not found or too old — installing from go.dev ...")
        if install_go(os_family, arch, dry_run) or dry_run:
            go_available = True
        else:
            print("[!] Go installation failed — continuing with fallbacks only ...\n")
    else:
        v = _go_version()
        print(f"[*] Go {v[0]}.{v[1]} already installed ✓\n")
        go_available = True

    # ── Step 3: git ───────────────────────────────────────────────────────────
    if go_available:
        _ensure_build_deps(pkg_mgr, dry_run)

    # ── Step 4: verify go env ─────────────────────────────────────────────────
    if go_available and not dry_run:
        if _test_go_install(dry_run):
            env = _go_env()
            print(f"[*] Go env verified  GOPATH={env['GOPATH']}  GOBIN={env['GOBIN']}\n")
        else:
            print("[!] Go env test failed — go install may not work correctly\n")

    # ── Step 5: install each tool ─────────────────────────────────────────────
    for tool_name, tool_def in TOOLS.items():
        if tool_name in excluded:
            print(f"  [-] {tool_name:<16} skipped (excluded)")
            continue
        if tool_def.get("optional") and not install_all:
            continue

        already = shutil.which(tool_name) or (
            (BIN_DIR / tool_name).is_file()
            and os.access(BIN_DIR / tool_name, os.X_OK)
            and str(BIN_DIR / tool_name))
        if already:
            print(f"  [✓] {tool_name:<16} already installed")
            continue

        print(f"  [>] {tool_name:<16} {tool_def['description']}")
        installed = False

        # pip tools (dirsearch)
        if "pip" in tool_def:
            if install_pip_tool(tool_def["pip"], dry_run):
                print(f"      [+] pip/pipx: {tool_def['pip']}  ✓")
                installed = True
            elif tool_def.get("git_clone") and install_dirsearch_git(dry_run):
                print("      [+] installed from git clone  ✓")
                installed = True
            if not installed:
                print(f"      [!] Failed. Try: pipx install {tool_def['pip']}")
            continue

        # go install (PRIMARY — before the package manager, finding #33)
        if tool_def.get("go_install") and (go_available or dry_run):
            ok, msg = install_via_go(_go_pkg_ref(tool_def), tool_def["binary_name"], dry_run)
            if ok:
                print("      [+] go install  ✓")
                installed = True
            else:
                print("      [i] go install failed:")
                for line in msg.splitlines():
                    if line.strip():
                        print(f"          {line}")

        # package manager fallback
        pm_pkg = tool_def.get(pkg_mgr) if pkg_mgr else None
        if not installed and pm_pkg:
            ok, msg = install_via_pm(pm_pkg, pkg_mgr, dry_run)
            if ok:
                print(f"      [+] {pkg_mgr}: {pm_pkg}  ✓")
                installed = True
                time.sleep(0.2)

        # GitHub binary fallback (verified)
        if not installed and tool_def.get("github_repo"):
            print("      [i] Trying GitHub binary fallback ...")
            ok, msg = download_and_install(tool_name, tool_def, os_family, arch, dry_run)
            if ok:
                print(f"      [+] GitHub binary ({msg})  ✓")
                installed = True
            else:
                print(f"      [i] GitHub binary: {msg}")
            time.sleep(0.3)

        # build from source (massdns)
        if not installed and tool_def.get("build_from_source"):
            print("      [i] Trying build from source ...")
            if build_massdns_from_source(dry_run):
                print("      [+] built from source  ✓")
                installed = True

        if not installed and not dry_run:
            req_flag = "REQUIRED" if tool_def.get("required") else "optional"
            print(f"      [!] All methods failed [{req_flag}]")
            if not github_token:
                print("          Tip: set GITHUB_TOKEN for reliable binary fallback")

    # ── Step 6: symlink ───────────────────────────────────────────────────────
    print("\n[*] Setting up recon_raptor command ...")
    create_symlink(dry_run)

    if dry_run:
        print("\n[i] Dry run — nothing installed.")
        print("    Run commands above, then verify: recon_raptor check")
    else:
        print("\n[+] Installation complete.")
        print("\n    IMPORTANT: open a new terminal to pick up Go PATH, then run:")
        print("      recon_raptor check")
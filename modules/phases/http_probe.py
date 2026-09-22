"""
modules/phases/http_probe.py

Phase 4: HTTP probing.

What this version fixes vs the previous one
───────────────────────────────────────────
· Per-host port targeting (finding #15)
    The old probe flattened every open port into one list and probed ALL
    of them on ALL hosts. This version maps each host to the ports open on
    its own IP(s) (via resolved.txt + ports.json) and probes host:port
    pairs — so a host with only 80/443 open isn't probed on some other
    host's 8983. The default web ports are always included per host as a
    safety net (CDN-fronted hosts whose real IPs naabu skipped). When the
    port-scan data isn't present, it falls back to the old global -ports
    behaviour.

· Wrong 'httpx' binary no longer silently caches empty results (finding #11)
    On Kali/Debian the python3-httpx package can put a *different* httpx on
    PATH; run with ProjectDiscovery flags it errors and finds nothing,
    which the scanner would then cache forever. This version:
      - warns up front if it can't confirm ProjectDiscovery httpx, and
      - RAISES on a clear invocation/flag failure with zero results, so the
        scanner treats the phase as failed and does NOT checkpoint it
        (it retries next run instead of caching an empty alive.txt).

· Handles both old/new httpx JSON field names (unchanged) and keeps the
  plain-text retry fallback.
"""

import json
import tempfile
from collections import defaultdict
from pathlib import Path

from modules.utils.process     import run_cmd
from modules.utils.output      import append_to_raw, write_clean, safe_print
from modules.phases.port_scanner import _NON_WEB

# stderr markers that mean "httpx rejected our flags" — i.e. wrong binary.
_INVOCATION_ERROR_MARKERS = (
    "flag provided but not defined", "unknown shorthand", "no such option",
    "flag needs an argument", "usage:", "invalid value for",
    "unrecognized arguments", "error: unrecognized",
)

_MAX_PORTS_PER_HOST = 30


def _parse_httpx_line(line: str):
    """Parse one httpx output line (old or new JSON field names)."""
    line = line.strip()
    if not line:
        return None

    if line.startswith('{'):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return None

        url = entry.get("url", "")
        if not url:
            return None

        status = (entry.get("status_code") or entry.get("status-code") or "")
        title  = str(entry.get("title", "") or "").replace('"', "'").strip()
        techs  = (entry.get("technologies") or entry.get("tech") or [])
        if isinstance(techs, str):
            techs = [techs]

        parts = [url, f"[{status}]"]
        if title:
            parts.append(f'"{title}"')
        if techs:
            parts.append(f"[{', '.join(str(t) for t in techs)}]")
        return "  ".join(parts)

    if line.startswith("http"):
        return line
    return None


def _confirm_pd_httpx() -> bool:
    """
    Best-effort check that `httpx` is ProjectDiscovery's, not the Python
    HTTP client's CLI. Conservative: only returns False when we're fairly
    confident it's wrong, so working setups are never falsely disabled.
    """
    stdout, stderr, rc = run_cmd(["httpx", "-version"], timeout=8)
    combined = (stdout + stderr).lower()
    if "projectdiscovery" in combined:
        return True
    # PD httpx accepts -version and prints a version string with rc 0.
    import re
    if rc == 0 and re.search(r'v?\d+\.\d+\.\d+', combined):
        return True
    # A clear usage/flag error on -version → almost certainly the wrong tool.
    if any(m in combined for m in _INVOCATION_ERROR_MARKERS):
        return False
    # Unsure — don't disrupt; assume OK.
    return True


def _build_perhost_targets(domain: str, subs_file: Path, out_dir: Path,
                           default_ports: list):
    """
    Build host:port probe targets from resolved.txt + ports.json.

    Returns (temp_file_path, host_count) or (None, 0) if the port-scan data
    isn't available (caller then falls back to global -ports).
    """
    ports_json = out_dir / "ports.json"
    resolved   = out_dir / "resolved.txt"
    if not (ports_json.exists() and resolved.exists()):
        return None, 0

    try:
        ip_ports = json.loads(ports_json.read_text())
    except Exception:
        return None, 0
    if not ip_ports:
        return None, 0

    host_ips = defaultdict(set)
    with open(resolved, 'r', errors='replace') as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 2:
                host_ips[parts[0].strip().lower()].add(parts[1].strip())

    with open(subs_file, 'r', errors='replace') as fh:
        hosts = [l.strip().lower() for l in fh if l.strip()]

    default_set = set(default_ports)
    lines = []
    for host in hosts:
        ports = set(default_set)                       # always-probe safety net
        for ip in host_ips.get(host, ()):
            for p in ip_ports.get(ip, ()):
                if p not in _NON_WEB:
                    ports.add(p)
        for p in sorted(ports)[:_MAX_PORTS_PER_HOST]:
            lines.append(f"{host}:{p}")

    if not lines:
        return None, 0

    tf = tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                     delete=False, prefix='rr_httpx_tgt_')
    tf.write('\n'.join(lines) + '\n')
    tf.close()
    return tf.name, len(hosts)


def run_http_probe(domain: str, subs_file: Path, out_dir: Path,
                   cfg: dict, available: dict, probe_ports: list = None):
    """Probe all targets for live web services."""
    raw_file   = out_dir / "subdomains_raw.txt"
    alive_file = out_dir / "alive.txt"

    if not available.get("httpx"):
        msg = "httpx not installed — HTTP probe skipped\n"
        safe_print(f"    [!] {msg.strip()}")
        append_to_raw(raw_file, "httpx", msg)
        return

    if not _confirm_pd_httpx():
        safe_print("    [!] The 'httpx' on PATH does not look like ProjectDiscovery's httpx.")
        safe_print("        (On Kali/Debian the python3-httpx package can shadow it.)")
        safe_print("        Install PD httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")

    threads = cfg.get('threads', 50)
    timeout = cfg.get('timeout', 10)
    default_ports = cfg.get('ports', [80, 443, 8080, 8443])

    # Prefer per-host targeting from the port scan; fall back to global ports.
    perhost_file, host_count = _build_perhost_targets(
        domain, subs_file, out_dir, default_ports)

    temp_to_clean = perhost_file
    try:
        if perhost_file:
            safe_print(f"    [i] Per-host port targeting from port scan "
                       f"({host_count} hosts)")
            base_cmd = ["httpx", "-l", perhost_file]
            ports_desc = "per-host"
        else:
            if probe_ports:
                ports_list = sorted(probe_ports)
            else:
                ports_list = default_ports
            ports_str = ','.join(str(p) for p in ports_list)
            base_cmd = ["httpx", "-l", str(subs_file), "-ports", ports_str]
            ports_desc = f"[{ports_str}]"

        with open(subs_file, 'r', errors='replace') as fh:
            sub_count = sum(1 for _ in fh)

        safe_print(f"    [>] httpx  {sub_count:,} hosts  ports {ports_desc} ...",
                   end='', flush=True)

        stdout, stderr, rc = run_cmd(base_cmd + [
            "-silent",
            "-threads",         str(threads),
            "-timeout",         str(timeout),
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
            "-json",
        ], timeout=1200)
        append_to_raw(raw_file, "httpx", stdout + stderr)

        alive_lines = [p for p in (_parse_httpx_line(l)
                                   for l in stdout.splitlines()) if p]

        # Invocation failure with no results → wrong binary / bad flags.
        # Raise so the scanner does NOT cache an empty alive.txt (#11).
        if not alive_lines and rc not in (0, -1):
            low = (stderr + stdout).lower()
            if any(m in low for m in _INVOCATION_ERROR_MARKERS):
                raise RuntimeError(
                    "httpx invocation failed (rc=%d) — likely the wrong 'httpx' "
                    "binary on PATH. Install ProjectDiscovery httpx and re-run." % rc)

        # Plain-text retry if JSON produced nothing but there was output.
        if not alive_lines and stdout.strip():
            sample = stdout.strip().splitlines()[:3]
            safe_print("\n    [!] JSON parse returned 0 results. Sample output:")
            for s in sample:
                safe_print(f"        {s[:120]}")
            safe_print("    [>] Retrying without -json ...", end='', flush=True)

            stdout2, stderr2, _ = run_cmd(base_cmd + [
                "-silent",
                "-threads", str(threads),
                "-timeout", str(timeout),
                "-sc",
            ], timeout=1200)
            append_to_raw(raw_file, "httpx_retry", stdout2 + stderr2)
            alive_lines += [p for p in (_parse_httpx_line(l)
                                        for l in stdout2.splitlines()) if p]

        count = write_clean(alive_file, alive_lines)
        safe_print(f" {count} alive")
        if count > 0:
            safe_print(f"    [+] alive.txt: {count} live hosts")
        else:
            safe_print("    [i] No live HTTP/HTTPS hosts found")
            safe_print("        Raw output saved in: subdomains_raw.txt")
    finally:
        if temp_to_clean:
            Path(temp_to_clean).unlink(missing_ok=True)
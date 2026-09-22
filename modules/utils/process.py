"""
modules/utils/process.py

Single consolidated subprocess runner used by every phase module.
Fixing a bug here fixes it everywhere — previously duplicated in 5 files.

What this version fixes vs the previous one
───────────────────────────────────────────
1. Tool resolution (finding #2, execution half):
   run_cmd / run_cmd_streaming now resolve the binary name against PATH
   *and* the installer's known dirs (/usr/local/bin, /usr/local/sbin,
   /opt/homebrew/bin) before launching. Previously a tool could be
   reported "available" by preflight (which checks those dirs) yet fail
   with FileNotFoundError at run time whenever sudo's secure_path
   excluded /usr/local/bin — the failure was swallowed and the phase
   silently produced nothing. Resolving centrally here fixes it for
   every phase at once, without editing each phase.

2. Partial output on timeout (finding #4):
   On timeout run_cmd now returns whatever the tool printed before it
   was killed, instead of "". Long tools (subfinder -all, dnsx, httpx,
   naabu) that legitimately run past their cap no longer come back
   completely empty.

3. Process-group kill (findings #4, #25):
   Children are launched in their own session/process group and killed
   as a group on timeout or on Ctrl+C. This reaps orphans such as the
   massdns process puredns spawns, and lets the scanner's SIGINT handler
   actually stop in-flight tools via kill_all_children().

4. Real streaming timeout (finding #26):
   run_cmd_streaming previously only checked the clock when a line
   arrived, so a genuinely silent-then-stuck process could run forever.
   A watchdog timer now enforces the timeout regardless of output.

Still needs other files: making preflight return resolved paths and
threading them through is not required anymore for correctness (this
layer resolves names), but is still worth doing for clarity.
"""

import os
import signal
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Optional, Callable

# Where our installer places binaries — checked in addition to PATH so a
# correctly-installed tool is still found when sudo's secure_path omits
# /usr/local/bin. Kept in sync with preflight._KNOWN_BIN_DIRS (plus the
# Apple-Silicon Homebrew prefix).
_KNOWN_BIN_DIRS = ["/usr/local/bin", "/usr/local/sbin", "/opt/homebrew/bin"]

# ── Live child-process registry (for Ctrl+C / timeout group kill) ─────────────
_active_lock  = threading.Lock()
_active_procs: set = set()


def _register(proc: subprocess.Popen) -> None:
    with _active_lock:
        _active_procs.add(proc)


def _deregister(proc: subprocess.Popen) -> None:
    with _active_lock:
        _active_procs.discard(proc)


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill a child and every process it spawned (e.g. puredns → massdns)."""
    if proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass


def kill_all_children() -> None:
    """
    Kill every currently-running child process group.
    Called by the scanner's SIGINT handler so Ctrl+C actually stops the
    tool that's running right now instead of waiting for it to finish.
    """
    with _active_lock:
        procs = list(_active_procs)
    for p in procs:
        _kill_group(p)


# ── Binary resolution ─────────────────────────────────────────────────────────

def resolve_binary(name: str) -> str:
    """
    Resolve a bare tool name to an absolute path.

    Order: leave any path-like argument untouched → shutil.which (PATH)
    → the installer's known bin dirs. Falls back to the original name if
    nothing is found, so the caller still gets a clean FileNotFoundError.
    """
    if os.sep in name or (os.altsep and os.altsep in name):
        return name  # already a path
    found = shutil.which(name)
    if found:
        return found
    for d in _KNOWN_BIN_DIRS:
        cand = Path(d) / name
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return name


def _start_kwargs() -> dict:
    kw: dict = {}
    if os.name == "posix":
        kw["start_new_session"] = True   # own process group → group kill
    return kw


# ── Buffered runner ───────────────────────────────────────────────────────────

def run_cmd(
    cmd: list,
    timeout: int = 300,
    input_data: Optional[str] = None,
) -> tuple:
    """
    Run a subprocess command safely (shell=False always).

    Returns:
        (stdout, stderr, returncode)

    Never raises — all exceptions return as stderr string with returncode -1.
    On timeout, returns whatever was captured before the kill (partial
    output), returncode -1, and a note in stderr.
    """
    if not cmd:
        return "", "[empty command]", -1

    resolved = [resolve_binary(cmd[0])] + [str(a) for a in cmd[1:]]

    try:
        proc = subprocess.Popen(
            resolved,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=(subprocess.PIPE if input_data is not None else None),
            text=True,
            **_start_kwargs(),
        )
    except FileNotFoundError:
        return "", f"[not found: {cmd[0]}]", -1
    except PermissionError:
        return "", f"[permission denied: {cmd[0]}]", -1
    except Exception as exc:
        return "", f"[error running {cmd[0]}: {exc}]", -1

    _register(proc)
    try:
        try:
            out, err = proc.communicate(input=input_data, timeout=timeout)
            return out or "", err or "", proc.returncode
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            try:
                out, err = proc.communicate(timeout=15)
            except Exception:
                out, err = "", ""
            note = f"[timeout after {timeout}s — {cmd[0]}; returning partial output]"
            merged_err = ((err or "") + "\n" + note).strip()
            return out or "", merged_err, -1
    finally:
        _deregister(proc)


# ── Streaming runner ──────────────────────────────────────────────────────────

def run_cmd_streaming(
    cmd: list,
    timeout: int = 7200,
    on_line: Optional[Callable[[str], None]] = None,
) -> tuple:
    """
    Like run_cmd, but streams stdout/stderr line-by-line in real time
    instead of buffering until the process exits.

    Use for long-running, otherwise-silent commands (puredns bruteforce,
    dnsx on huge wordlists) where a buffered run would make the terminal
    look frozen for hours even while the command is actively working.

    on_line: optional callback(line) called for each output line as it
             arrives. If None, lines are printed with a carriage-return
             prefix so progress overwrites in place.

    Returns (full_captured_output, "", returncode) — stderr is merged
    into stdout since ordering matters more than separation for progress.

    The timeout is enforced by a watchdog timer, so a process that goes
    silent and hangs is still killed on schedule.
    """
    if not cmd:
        return "", "[empty command]", -1

    resolved = [resolve_binary(cmd[0])] + [str(a) for a in cmd[1:]]

    try:
        proc = subprocess.Popen(
            resolved,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            **_start_kwargs(),
        )
    except FileNotFoundError:
        return "", f"[not found: {cmd[0]}]", -1
    except PermissionError:
        return "", f"[permission denied: {cmd[0]}]", -1
    except Exception as exc:
        return "", f"[error running {cmd[0]}: {exc}]", -1

    _register(proc)

    timed_out = threading.Event()

    def _on_timeout():
        timed_out.set()
        _kill_group(proc)

    watchdog = threading.Timer(timeout, _on_timeout)
    watchdog.daemon = True
    watchdog.start()

    captured = []
    try:
        for line in proc.stdout:            # ends when the pipe closes
            captured.append(line)
            clean = line.rstrip()
            if clean:
                if on_line:
                    on_line(clean)
                else:
                    print(f"\r        {clean[:100]}", end="", flush=True)
        proc.wait(timeout=15)
    except Exception:
        pass
    finally:
        watchdog.cancel()
        _deregister(proc)

    if on_line is None:
        print()   # newline after the last \r-overwritten progress line

    output = ''.join(captured)
    if timed_out.is_set():
        output += f"\n[timeout after {timeout}s]"
        return output, "", -1

    rc = proc.returncode if proc.returncode is not None else -1
    return output, "", rc


# ── Version helper ────────────────────────────────────────────────────────────

def tool_version(name: str, version_cmd: list) -> Optional[str]:
    """
    Return a tool's version string, or None if not installed.
    Uses run_cmd so it's consistent with phase tool detection, and
    resolves the binary the same way execution does.
    """
    import re
    if resolve_binary(name) == name and not shutil.which(name):
        # resolve_binary returned the bare name unchanged → not found anywhere
        return None
    stdout, stderr, _ = run_cmd(version_cmd, timeout=5)
    combined = (stdout + stderr).strip()
    m = re.search(r'v?\d+\.\d+[\.\d]*', combined)
    return m.group(0) if m else "found"
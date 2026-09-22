"""
modules/utils/network.py

HTTP helpers for IP enrichment.

ip-api.com batch endpoint:
  POST http://ip-api.com/batch?fields=...
  Up to 100 IPs per request, free tier ~45 requests/min.
  (Free tier is HTTP-only — HTTPS needs a paid key. We honor the rate-limit
   headers instead of hammering it.)

What this version fixes vs the previous one
───────────────────────────────────────────
· Token never leaks into logs (finding #38)
    requests' HTTPError text includes the full URL, which for the MMDB
    download contains ?token=<secret>. _mask() existed but was never used;
    it's now applied to every error string before printing.

· Atomic MMDB download (finding #39)
    download_file() writes to a .part file and os.replace()s it into place
    only on success. A failed/partial download can no longer overwrite or
    delete a good existing database.

· ip-api rate limiting is handled (finding #39)
    Batches are retried with backoff; HTTP 429 waits the X-Ttl the API
    reports; when the remaining-request header hits zero we pause for the
    window to reset. IPs in a batch that ultimately fails are counted and
    reported instead of silently vanishing.
"""

import os
import re
import time
import json as _json
from pathlib import Path
from typing import Optional

try:
    import requests as _req
    _REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    _REQUESTS = False

_UA     = "recon-raptor/1.0 (github.com/yourorg/recon_raptor)"
_FIELDS = "status,country,countryCode,regionName,city,isp,org,as,query,proxy,hosting"
_BATCH_URL   = f"http://ip-api.com/batch?fields={_FIELDS}"
_BATCH_SIZE  = 100
_BATCH_DELAY = 1.4     # ~42 batches/min, under the 45/min free limit
_MAX_BATCH_RETRIES = 3


def _mask(text: str) -> str:
    """Mask token=… (and Bearer tokens) anywhere in a string before logging."""
    text = re.sub(r'(token=)[^&\s]+', r'\1***', str(text))
    text = re.sub(r'(Bearer\s+)\S+', r'\1***', text)
    return text


# ── Simple GET/POST JSON ──────────────────────────────────────────────────────

def http_get_json(url: str, timeout: int = 30,
                  headers: Optional[dict] = None) -> Optional[dict]:
    """GET url and return parsed JSON, or None on any error."""
    hdrs = {"User-Agent": _UA}
    if headers:
        hdrs.update(headers)
    try:
        if _REQUESTS:
            r = _req.get(url, headers=hdrs, timeout=timeout)
            r.raise_for_status()
            return r.json()
        else:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _json.loads(resp.read().decode())
    except Exception:
        return None


def _post_batch(payload: list, timeout: int = 30):
    """
    POST one ip-api batch.
    Returns (data_or_None, wait_seconds) — wait_seconds is how long the
    caller should pause before the next request (0 when not rate limited).
    """
    hdrs = {"User-Agent": _UA, "Content-Type": "application/json"}
    body = _json.dumps(payload).encode()
    try:
        if _REQUESTS:
            r = _req.post(_BATCH_URL, data=body, headers=hdrs, timeout=timeout)
            if r.status_code == 429:
                ttl = int(r.headers.get("X-Ttl", "5") or 5)
                return None, ttl + 1
            r.raise_for_status()
            data = r.json()
            # Proactively pause if we've exhausted the current window.
            try:
                remaining = int(r.headers.get("X-Rl", "1"))
                ttl       = int(r.headers.get("X-Ttl", "0"))
            except ValueError:
                remaining, ttl = 1, 0
            wait = (ttl + 1) if remaining <= 0 else 0
            return data, wait
        else:
            req = urllib.request.Request(_BATCH_URL, data=body,
                                         headers=hdrs, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _json.loads(resp.read().decode()), 0
    except urllib.error.HTTPError as exc:   # type: ignore[name-defined]
        if getattr(exc, "code", None) == 429:
            ttl = exc.headers.get("X-Ttl") or exc.headers.get("Retry-After") or "5"
            try:
                return None, int(ttl) + 1
            except ValueError:
                return None, 5
        return None, 0
    except Exception:
        return None, 0


def batch_ip_lookup(ips: list) -> dict:
    """
    Query ip-api.com for all IPs (batched, rate-limit aware).
    Returns {ip: data_dict} for successful responses. Failed batches are
    retried; IPs that still fail are counted and reported.
    """
    if not ips:
        return {}

    results   = {}
    total     = len(ips)
    processed = 0
    failed    = 0

    for i in range(0, total, _BATCH_SIZE):
        chunk   = ips[i: i + _BATCH_SIZE]
        payload = [{"query": ip} for ip in chunk]

        data, wait = None, 0
        for attempt in range(1, _MAX_BATCH_RETRIES + 1):
            data, wait = _post_batch(payload)
            if data is not None and isinstance(data, list):
                break
            time.sleep(max(wait, _BATCH_DELAY * attempt))

        if data and isinstance(data, list):
            for entry in data:
                ip = entry.get("query", "")
                if ip and entry.get("status") == "success":
                    results[ip] = entry
        else:
            failed += len(chunk)

        processed += len(chunk)
        if total > _BATCH_SIZE:
            pct = processed / total * 100
            print(f"\r        {processed}/{total} IPs enriched ({pct:.0f}%)",
                  end="", flush=True)

        if processed < total:
            time.sleep(wait if wait else _BATCH_DELAY)

    if total > _BATCH_SIZE:
        print()
    if failed:
        print(f"        [!] {failed} IP(s) could not be enriched via ip-api "
              f"(rate limit or transient errors)")

    return results


# ── File download (atomic, token-masked) ──────────────────────────────────────

def download_file(url: str, dest, show_progress: bool = True) -> bool:
    """
    Download url to *dest* atomically: write to <dest>.part, then os.replace
    into place only on success. A failed download never overwrites or removes
    an existing good file. Token values are masked in any printed output.
    """
    dest = Path(dest)
    part = dest.with_name(dest.name + ".part")

    try:
        if _REQUESTS:
            r = _req.get(url, stream=True, timeout=120)
            r.raise_for_status()
            total    = int(r.headers.get("content-length", 0))
            received = 0
            with open(part, "wb") as fh:
                for chunk in r.iter_content(chunk_size=65536):
                    fh.write(chunk)
                    received += len(chunk)
                    if show_progress and total:
                        pct = received / total * 100
                        mb  = received / 1_048_576
                        print(f"\r        {mb:6.1f} MB / {total/1_048_576:.1f} MB"
                              f"  ({pct:5.1f}%)", end="", flush=True)
            if show_progress and total:
                print()
        else:
            import subprocess
            r = subprocess.run(["curl", "-fL", "--progress-bar", "-o", str(part), url],
                               capture_output=True, text=True, timeout=300)
            if r.returncode != 0:
                raise RuntimeError(_mask(r.stderr or "curl failed"))

        os.replace(part, dest)   # atomic swap into place
        return True
    except Exception as exc:
        try:
            part.unlink(missing_ok=True)   # remove partial, keep existing dest
        except Exception:
            pass
        print(f"\n    [!] Download failed: {_mask(exc)}")
        return False
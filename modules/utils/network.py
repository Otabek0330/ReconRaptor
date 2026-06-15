"""
modules/utils/network.py

HTTP helpers for IP enrichment.

ip-api.com batch endpoint:
  POST http://ip-api.com/batch?fields=...
  Body: [{"query": "1.2.3.4"}, ...]
  Max 100 IPs per request.
  Rate limit: 45 requests/min (free tier) = up to 4,500 IPs/min.
  No API key needed.

ipinfo.io:
  Used via MMDB download only — see enrichment.py.
"""

import time
import json as _json
from typing import Optional

try:
    import requests as _req
    _REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    _REQUESTS = False

_UA     = "recon-raptor/1.0 (github.com/yourorg/recon_raptor)"
_FIELDS = (
    "status,country,countryCode,regionName,city,"
    "isp,org,as,query,proxy,hosting"
)
_BATCH_URL   = f"http://ip-api.com/batch?fields={_FIELDS}"
_BATCH_SIZE  = 100      # ip-api.com max per request
_BATCH_DELAY = 1.4      # seconds between batch calls (~42 req/min, under 45 limit)


def http_get_json(url: str, timeout: int = 10,
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


def _post_json(url: str, payload: list, timeout: int = 30) -> Optional[list]:
    """POST JSON payload and return parsed JSON list, or None on error."""
    hdrs = {
        "User-Agent":   _UA,
        "Content-Type": "application/json",
    }
    body = _json.dumps(payload).encode()
    try:
        if _REQUESTS:
            r = _req.post(url, data=body, headers=hdrs, timeout=timeout)
            r.raise_for_status()
            return r.json()
        else:
            req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _json.loads(resp.read().decode())
    except Exception:
        return None


def batch_ip_lookup(ips: list[str]) -> dict[str, dict]:
    """
    Query ip-api.com for every IP in *ips* using the batch endpoint.

    Sends up to 100 IPs per POST request.
    Automatically paginates with a delay to respect the rate limit.

    Returns {ip: data_dict} for every IP that returned a success response.
    """
    if not ips:
        return {}

    results    = {}
    total      = len(ips)
    processed  = 0

    # Split into chunks of BATCH_SIZE
    for i in range(0, total, _BATCH_SIZE):
        chunk   = ips[i : i + _BATCH_SIZE]
        payload = [{"query": ip} for ip in chunk]

        data = _post_json(_BATCH_URL, payload)
        if data and isinstance(data, list):
            for entry in data:
                ip = entry.get("query", "")
                if ip and entry.get("status") == "success":
                    results[ip] = entry

        processed += len(chunk)
        remaining  = total - processed

        # Show progress for large sets
        if total > _BATCH_SIZE:
            pct = processed / total * 100
            print(
                f"\r        {processed}/{total} IPs enriched ({pct:.0f}%)",
                end="", flush=True,
            )

        # Rate-limit delay between batches (skip after the last one)
        if remaining > 0:
            time.sleep(_BATCH_DELAY)

    if total > _BATCH_SIZE:
        print()  # newline after progress

    return results


def ipinfo_lookup(ip: str, token: str) -> Optional[dict]:
    """
    Single IP lookup via ipinfo.io API.
    Kept for compatibility — MMDB download is preferred over this.
    Free tier: 50k requests/month.
    """
    return http_get_json(
        f"https://ipinfo.io/{ip}?token={token}",
        timeout=10,
    )

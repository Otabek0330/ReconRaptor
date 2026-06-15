"""
modules/phases/enrichment.py

Phase 5: IP enrichment.

Strategy (in priority order):
  1. ipinfo MMDB  — if token is set in config, download ipinfo_lite.mmdb once,
                    then query all IPs locally.  No rate limits, millisecond
                    lookups, auto-refreshes every 7 days.
  2. ip-api.com   — free fallback when no token is set or MMDB is unavailable.
                    Rate-limited to ~40 req/min (no key needed).

Download URL:
  https://ipinfo.io/data/ipinfo_lite.mmdb?_src=frontend&token=<token>

Output:
  ip_enrichment.json   full JSON record per IP
  ip_summary.txt       human-readable one-liner per IP
"""

import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

try:
    import maxminddb
    _MMDB_OK = True
except ImportError:
    _MMDB_OK = False

try:
    import requests as _req
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

BASE_DIR         = Path(__file__).parent.parent.parent
MMDB_DEFAULT     = BASE_DIR / "ipinfo_lite.mmdb"
MMDB_MAX_AGE     = timedelta(days=7)
MMDB_DOWNLOAD    = "https://ipinfo.io/data/ipinfo_lite.mmdb?_src=frontend&token={token}"


# ── CDN / cloud detection ─────────────────────────────────────────────────────

_CDN_ASN = {
    "13335":  "Cloudflare",   "209242": "Cloudflare",   "394536": "Cloudflare",
    "54113":  "Fastly",
    "16625":  "Akamai",       "20940":  "Akamai",
    "15169":  "Google CDN",   "396982": "Google CDN",
    "14618":  "Amazon CloudFront", "16509": "Amazon CloudFront",
    "8075":   "Microsoft Azure CDN",
    "32934":  "Meta / Facebook",
    "60068":  "CDN77",
    "22822":  "Limelight / Edgio",
    "30148":  "Sucuri / GoDaddy",
}

_CDN_ORG_KW = [
    ("cloudflare",  "Cloudflare"),    ("fastly",     "Fastly"),
    ("akamai",      "Akamai"),        ("cloudfront", "Amazon CloudFront"),
    ("incapsula",   "Imperva"),       ("imperva",    "Imperva"),
    ("sucuri",      "Sucuri"),        ("stackpath",  "StackPath"),
    ("cdn77",       "CDN77"),         ("keycdn",     "KeyCDN"),
    ("bunnycdn",    "BunnyCDN"),      ("limelight",  "Limelight / Edgio"),
    ("edgio",       "Edgio"),         ("azion",      "Azion"),
    ("g-core",      "G-Core"),        ("gcore",      "G-Core"),
    ("zscaler",     "Zscaler"),       ("level3",     "Lumen / Level3"),
    ("verizon",     "Verizon / Edgio"),
]


def _detect_cdn(data: dict) -> str | None:
    asn_field = data.get("as", "") or data.get("asn", "")
    org       = (data.get("org", "")     or "").lower()
    isp       = (data.get("isp", "")     or "").lower()
    as_name   = (data.get("as_name", "") or "").lower()

    asn_num = str(asn_field).lstrip("AS").split()[0]
    if asn_num in _CDN_ASN:
        return _CDN_ASN[asn_num]

    combined = f"{org} {isp} {as_name}"
    for kw, provider in _CDN_ORG_KW:
        if kw in combined:
            return provider

    return None


# ── MMDB helpers ──────────────────────────────────────────────────────────────

def _mmdb_path(cfg: dict) -> Path:
    raw = (cfg.get("mmdb_path") or "").strip()
    return Path(raw) if raw else MMDB_DEFAULT


def _mmdb_stale(path: Path) -> bool:
    if not path.exists():
        return True
    age = datetime.now() - datetime.fromtimestamp(path.stat().st_mtime)
    return age > MMDB_MAX_AGE


def download_mmdb(token: str, dest: Path) -> bool:
    """
    Download ipinfo_lite.mmdb to *dest*.
    Shows a simple progress indicator.
    Returns True on success.
    """
    url = MMDB_DOWNLOAD.format(token=token)
    print(f"    [>] Downloading ipinfo_lite.mmdb → {dest}")
    print(f"        (this happens once, then refreshes every 7 days)")

    try:
        if _REQUESTS:
            r = _req.get(url, stream=True, timeout=120)
            r.raise_for_status()
            total    = int(r.headers.get("content-length", 0))
            received = 0
            with open(dest, "wb") as fh:
                for chunk in r.iter_content(chunk_size=65536):
                    fh.write(chunk)
                    received += len(chunk)
                    if total:
                        pct = received / total * 100
                        mb  = received / 1_048_576
                        print(
                            f"\r        {mb:6.1f} MB  /  "
                            f"{total/1_048_576:.1f} MB  ({pct:5.1f}%)",
                            end="", flush=True,
                        )
            print()
        else:
            subprocess.run(
                ["curl", "-L", "--progress-bar", "-o", str(dest), url],
                check=True, timeout=300,
            )

        size_mb = dest.stat().st_size / 1_048_576
        print(f"    [+] MMDB saved: {size_mb:.1f} MB")
        return True

    except Exception as exc:
        print(f"\n    [!] MMDB download failed: {exc}")
        dest.unlink(missing_ok=True)
        return False


def _lookup_mmdb(reader, ip: str) -> dict:
    try:
        return reader.get(ip) or {}
    except Exception:
        return {}


def _normalise_mmdb(ip: str, raw: dict) -> dict:
    """
    Normalise an ipinfo_lite.mmdb record into our internal schema.

    ipinfo_lite fields:
      asn, as_name, as_domain, country_code, country
      (city / region present in some editions)
    """
    asn = raw.get("asn", "")
    return {
        "query":       ip,
        "status":      "success",
        "source":      "ipinfo_mmdb",
        "country":     raw.get("country",      ""),
        "countryCode": raw.get("country_code", ""),
        "city":        raw.get("city",         ""),
        "regionName":  raw.get("region",       ""),
        "isp":         raw.get("as_name",      ""),
        "org":         raw.get("as_name",      ""),
        "as":          f"{asn} {raw.get('as_name', '')}".strip(),
        "asn":         asn,
        "as_name":     raw.get("as_name",   ""),
        "as_domain":   raw.get("as_domain", ""),
    }


# ── Main entrypoint ───────────────────────────────────────────────────────────

def run_enrichment(domain: str, ips_file: Path, out_dir: Path, cfg: dict):
    ips = [l.strip() for l in ips_file.read_text(errors="replace").splitlines()
           if l.strip()]
    if not ips:
        print("    [i] No IPs to enrich")
        return

    token    = (cfg.get("tokens", {}) or {}).get("ipinfo", "") or ""
    db_path  = _mmdb_path(cfg)
    ip_data  = {}

    # ── Primary path: ipinfo MMDB ─────────────────────────────────────────────
    if token:
        if not _MMDB_OK:
            print("    [!] maxminddb library not installed.")
            print("        Run: pip install maxminddb")
            print("    [i] Falling back to ip-api.com")
        else:
            if _mmdb_stale(db_path):
                ok = download_mmdb(token, db_path)
                if not ok:
                    print("    [i] Falling back to ip-api.com")

            if db_path.exists():
                print(f"    [>] Looking up {len(ips)} IPs in local MMDB ...", end="", flush=True)
                with maxminddb.open_database(str(db_path)) as reader:
                    for ip in ips:
                        raw = _lookup_mmdb(reader, ip)
                        if raw:
                            ip_data[ip] = _normalise_mmdb(ip, raw)
                print(f" {len(ip_data)}/{len(ips)} found")

    # ── Fallback: ip-api.com ──────────────────────────────────────────────────
    missing = [ip for ip in ips if ip not in ip_data]
    if missing:
        if token:
            reason = "MMDB unavailable"
        else:
            reason = "no ipinfo token configured"
        print(f"    [>] ip-api.com ({reason}) — {len(missing)} IPs, rate-limited ...")
        from modules.utils.network import batch_ip_lookup
        fallback = batch_ip_lookup(missing)
        ip_data.update(fallback)
        print(f"    [+] ip-api.com: {len(fallback)}/{len(missing)} IPs enriched")

    # ── CDN detection ─────────────────────────────────────────────────────────
    cdn_ips = []
    for ip, data in ip_data.items():
        cdn = _detect_cdn(data)
        data["cdn"] = cdn
        if cdn:
            cdn_ips.append((ip, cdn))

    # ── Write outputs ─────────────────────────────────────────────────────────
    (out_dir / "ip_enrichment.json").write_text(json.dumps(ip_data, indent=2))

    summary = []
    for ip, d in sorted(ip_data.items()):
        country = d.get("country", "?")
        city    = d.get("city") or d.get("regionName") or "?"
        asn     = d.get("as", "")
        cdn     = d.get("cdn", "")
        tag     = f"  [{cdn}]" if cdn else ""
        summary.append(f"{ip:<18} {country}/{city:<16}  {asn}{tag}")

    (out_dir / "ip_summary.txt").write_text("\n".join(summary) + "\n")

    print(f"    [+] ip_enrichment.json: {len(ip_data)} IPs")
    print(f"    [+] ip_summary.txt written")
    if cdn_ips:
        print(f"    [+] CDN / cloud protected: {len(cdn_ips)} IPs")
        for ip, provider in cdn_ips:
            print(f"        {ip:<18} {provider}")

"""
modules/phases/enrichment.py

Phase 7: IP enrichment.

Strategy:
  1. ipinfo MMDB  — download once (atomically, via network.download_file),
     query locally, no rate limits
  2. ip-api.com   — free batch fallback (rate-limit aware, see network.py)

What this version fixes vs the previous one
───────────────────────────────────────────
· CDN vs cloud classification (finding #24)
    The old table labelled all of AWS (AS16509), Google (AS15169) and Azure
    (AS8075) as "CDN", and treated transit carriers (level3, verizon) as
    CDNs too. That's wrong: a host on raw EC2 is cloud-hosted with a
    reachable origin, not hidden behind a CDN/WAF. This version separates:
      · cdn   — true CDN / WAF fronting (Cloudflare, Fastly, Akamai,
                CloudFront, Sucuri, Imperva, …) where the origin is masked
      · cloud — cloud/hosting providers (AWS, GCP, Azure, DigitalOcean, …)
    CloudFront is matched by org keyword (its ASN overlaps plain AWS, so ASN
    alone can't distinguish it). Transit-only carriers are no longer flagged.

    Both fields are written per IP; the report's CDN count is now accurate
    (true CDNs only), and cloud-hosted IPs are reported separately.
"""

import re
import json
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta

try:
    import maxminddb
    _MMDB_OK = True
except ImportError:
    _MMDB_OK = False

from modules.utils.output  import safe_print
from modules.utils.network import batch_ip_lookup, download_file

BASE_DIR      = Path(__file__).parent.parent.parent
MMDB_DEFAULT  = BASE_DIR / "ipinfo_lite.mmdb"
MMDB_MAX_AGE  = timedelta(days=7)
MMDB_DOWNLOAD = "https://ipinfo.io/data/ipinfo_lite.mmdb?_src=frontend&token={token}"

# ── True CDN / WAF fronting ───────────────────────────────────────────────────
# These sit in front of an origin — a hit means the real host is masked.
_CDN_ASN = {
    "13335": "Cloudflare", "209242": "Cloudflare", "394536": "Cloudflare",
    "54113": "Fastly",
    "16625": "Akamai",     "20940":  "Akamai",     "16702": "Akamai",
    "60068": "CDN77",
    "22822": "Edgio / Limelight",
    "30148": "Sucuri",
    "19551": "Imperva / Incapsula",
    "12989": "Imperva",
    "393234": "StackPath",
}
_CDN_ORG_KW = [
    ("cloudflare", "Cloudflare"),   ("fastly",    "Fastly"),
    ("akamai",     "Akamai"),       ("cloudfront", "Amazon CloudFront"),
    ("incapsula",  "Imperva"),      ("imperva",   "Imperva"),
    ("sucuri",     "Sucuri"),       ("stackpath", "StackPath"),
    ("cdn77",      "CDN77"),        ("keycdn",    "KeyCDN"),
    ("bunnycdn",   "BunnyCDN"),     ("bunny.net", "BunnyCDN"),
    ("limelight",  "Edgio / Limelight"), ("edgio",  "Edgio"),
    ("azion",      "Azion"),        ("g-core",    "G-Core"),
    ("gcore",      "G-Core"),       ("section.io", "Section"),
    ("zscaler",    "Zscaler"),
]

# ── Cloud / hosting providers ─────────────────────────────────────────────────
# The origin is likely directly reachable — hosting, not CDN fronting.
_CLOUD_ASN = {
    "16509": "Amazon AWS",   "14618": "Amazon AWS",
    "15169": "Google Cloud", "396982": "Google Cloud", "19527": "Google Cloud",
    "8075":  "Microsoft Azure", "8068": "Microsoft Azure", "8069": "Microsoft Azure",
    "14061": "DigitalOcean",
    "16276": "OVH",
    "24940": "Hetzner",
    "63949": "Akamai (Linode)", "20473": "Vultr / Choopa",
    "14421": "Oracle Cloud",  "31898": "Oracle Cloud",
    "45102": "Alibaba Cloud", "37963": "Alibaba Cloud",
}
_CLOUD_ORG_KW = [
    ("amazon",       "Amazon AWS"),      ("aws",          "Amazon AWS"),
    ("google cloud", "Google Cloud"),    ("google llc",   "Google"),
    ("microsoft",    "Microsoft Azure"), ("azure",        "Microsoft Azure"),
    ("digitalocean", "DigitalOcean"),    ("ovh",          "OVH"),
    ("hetzner",      "Hetzner"),         ("linode",       "Linode"),
    ("vultr",        "Vultr"),           ("oracle",       "Oracle Cloud"),
    ("alibaba",      "Alibaba Cloud"),   ("tencent",      "Tencent Cloud"),
    ("scaleway",     "Scaleway"),        ("contabo",      "Contabo"),
]


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or
                    addr.is_link_local or addr.is_multicast or
                    addr.is_reserved or addr.is_unspecified)
    except ValueError:
        return False


def _extract_asn_num(asn_field: str) -> str:
    m = re.search(r'\d+', str(asn_field))
    return m.group(0) if m else ""


def _classify(data: dict):
    """
    Return (cdn, cloud): cdn is a true CDN/WAF name or None; cloud is a
    cloud/hosting provider name or None. CDN takes precedence when both
    could match (a CDN edge IP is what the client actually talks to).
    """
    asn_field = data.get("as", "") or data.get("asn", "")
    org       = (data.get("org", "") or "").lower()
    isp       = (data.get("isp", "") or "").lower()
    as_name   = (data.get("as_name", "") or "").lower()
    combined  = f"{org} {isp} {as_name}"
    asn_num   = _extract_asn_num(str(asn_field))

    # CDN by keyword first (catches CloudFront, whose ASN overlaps AWS).
    for kw, provider in _CDN_ORG_KW:
        if kw in combined:
            return provider, None
    if asn_num in _CDN_ASN:
        return _CDN_ASN[asn_num], None

    # Otherwise, cloud/hosting.
    if asn_num in _CLOUD_ASN:
        return None, _CLOUD_ASN[asn_num]
    for kw, provider in _CLOUD_ORG_KW:
        if kw in combined:
            return None, provider

    return None, None


# ── MMDB helpers ──────────────────────────────────────────────────────────────

def _mmdb_path(cfg: dict) -> Path:
    raw = (cfg.get("mmdb_path") or "").strip()
    return Path(raw) if raw else MMDB_DEFAULT


def _mmdb_stale(path: Path) -> bool:
    if not path.exists():
        return True
    age = datetime.now() - datetime.fromtimestamp(path.stat().st_mtime)
    return age > MMDB_MAX_AGE


def _normalise_mmdb(ip: str, raw: dict) -> dict:
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
    with open(ips_file, 'r', errors='replace') as fh:
        all_ips = [l.strip() for l in fh if l.strip()]

    if not all_ips:
        safe_print("    [i] No IPs to enrich")
        return

    public_ips = [ip for ip in all_ips if _is_public(ip)]
    private_ct = len(all_ips) - len(public_ips)
    if private_ct:
        safe_print(f"    [i] Filtered {private_ct} private/loopback IPs (RFC 1918)")
    if not public_ips:
        safe_print("    [i] No public IPs to enrich")
        return

    token   = (cfg.get("tokens", {}) or {}).get("ipinfo", "") or ""
    db_path = _mmdb_path(cfg)
    ip_data = {}

    # ── Primary: ipinfo MMDB ──────────────────────────────────────────────────
    if token:
        if not _MMDB_OK:
            safe_print("    [!] maxminddb not installed: pip install maxminddb")
            safe_print("    [i] Falling back to ip-api.com")
        else:
            if _mmdb_stale(db_path):
                safe_print(f"    [>] Downloading ipinfo_lite.mmdb → {db_path}")
                safe_print("        (refreshes every 7 days, queries locally)")
                url = MMDB_DOWNLOAD.format(token=token)
                if not download_file(url, db_path, show_progress=True):
                    safe_print("    [i] MMDB download failed — falling back to ip-api.com")

            if db_path.exists():
                safe_print(f"    [>] MMDB lookup: {len(public_ips)} IPs ...",
                           end='', flush=True)
                try:
                    with maxminddb.open_database(str(db_path)) as reader:
                        for ip in public_ips:
                            try:
                                raw = reader.get(ip) or {}
                                if raw:
                                    ip_data[ip] = _normalise_mmdb(ip, raw)
                            except Exception:
                                pass
                    safe_print(f" {len(ip_data)}/{len(public_ips)} found")
                except Exception as exc:
                    safe_print(f"\n    [!] MMDB read error: {exc}")
                    safe_print("    [i] Falling back to ip-api.com")
                    ip_data = {}

    # ── Fallback: ip-api.com batch endpoint ───────────────────────────────────
    missing = [ip for ip in public_ips if ip not in ip_data]
    if missing:
        reason = "no ipinfo token" if not token else "MMDB unavailable"
        safe_print(f"    [>] ip-api.com ({reason}) — {len(missing)} IPs ...")
        fallback = batch_ip_lookup(missing)
        ip_data.update(fallback)
        safe_print(f"    [+] ip-api.com: {len(fallback)}/{len(missing)} enriched")

    # ── CDN / cloud classification ────────────────────────────────────────────
    cdn_ips, cloud_ips = [], []
    for ip, data in ip_data.items():
        cdn, cloud = _classify(data)
        data["cdn"]   = cdn
        data["cloud"] = cloud
        if cdn:
            cdn_ips.append((ip, cdn))
        elif cloud:
            cloud_ips.append((ip, cloud))

    # ── Write outputs ─────────────────────────────────────────────────────────
    (out_dir / "ip_enrichment.json").write_text(json.dumps(ip_data, indent=2))

    summary = []
    for ip, d in sorted(ip_data.items()):
        country = d.get("country", "?")
        city    = d.get("city") or d.get("regionName") or "?"
        asn     = d.get("as", "")
        tag     = ""
        if d.get("cdn"):
            tag = f"  [CDN: {d['cdn']}]"
        elif d.get("cloud"):
            tag = f"  [cloud: {d['cloud']}]"
        summary.append(f"{ip:<18} {country}/{city:<16}  {asn}{tag}")
    (out_dir / "ip_summary.txt").write_text('\n'.join(summary) + '\n')

    safe_print(f"    [+] ip_enrichment.json: {len(ip_data)} IPs enriched")
    safe_print("    [+] ip_summary.txt written")
    if cdn_ips:
        safe_print(f"    [+] CDN / WAF fronted: {len(cdn_ips)} IPs")
        for ip, provider in cdn_ips:
            safe_print(f"        {ip:<18} {provider}")
    if cloud_ips:
        safe_print(f"    [+] Cloud-hosted (origin likely reachable): {len(cloud_ips)} IPs")
        for ip, provider in cloud_ips[:15]:
            safe_print(f"        {ip:<18} {provider}")
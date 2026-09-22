"""
modules/phases/extras.py

Phase 5 / Phase 8: high-value extras with minimal extra tooling.

  harvest_robots_and_sitemaps()  — robots.txt + sitemap paths → traversal seed
  analyse_email_security()       — SPF / DMARC / DKIM analysis from DNS records

What this version fixes vs the previous one
───────────────────────────────────────────
Email security (finding #6, evaluation half — the data half is in resolver.py):
  · Per-host evaluation, not global. Previously a single subdomain with an
    SPF record suppressed the "SPF missing" finding for the apex; DMARC/DKIM
    were only ever checked for the apex. Now SPF is evaluated on every host
    that has one, "missing" is reported per mail-relevant host (apex + MX
    hosts), and DMARC is checked per host via the _dmarc.<host> records
    resolver.py now collects.
  · `v=spf1 redirect=...` is no longer flagged as "no all mechanism" — a
    redirect legitimately delegates the policy.
  · Multiple SPF records on one host are flagged as an RFC permerror
    (SPF silently ignored).

Harvest:
  · robots "User-Agent" match is case-insensitive (finding #23).
  · Harvested paths are stored WITHOUT a leading slash, so ffuf's
    {url}/FUZZ no longer builds `host//admin` (finding #18).
  · Regex/wildcard robots entries (`/*.pdf$`, globs) are dropped (#18).
  · Sitemap: directives are only followed when in-scope; sitemap indexes
    are recursed one level; .gz sitemaps are decompressed; response size is
    capped; XML is parsed with defusedxml when available (finding #23).
  · Hosts are harvested in parallel over a shared session with TLS verify
    off, so self-signed hosts aren't silently skipped and 1000 hosts don't
    take hours (findings #23, #41).
"""

import re
import gzip
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

from modules.utils.output import safe_print, write_clean

try:
    import requests as _req
    _REQUESTS = True
    try:
        import urllib3
        urllib3.disable_warnings()   # recon fetches use verify=False on purpose
    except Exception:
        pass
except ImportError:
    import urllib.request
    _REQUESTS = False

# Prefer defusedxml for untrusted XML; fall back to stdlib if unavailable.
try:
    import defusedxml.ElementTree as _ET
    _DEFUSED = True
except ImportError:
    import xml.etree.ElementTree as _ET
    _DEFUSED = False

_MAX_BYTES        = 3 * 1024 * 1024   # cap any single fetched document
_MAX_INDEX_CHILDREN = 25              # cap sitemap-index recursion fan-out
_HARVEST_WORKERS  = 10
_UA = "recon-raptor/1.0"


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _fetch(url: str, session=None, timeout: int = 10) -> bytes:
    """Fetch URL, returning up to _MAX_BYTES of raw bytes ('' on any error)."""
    try:
        if _REQUESTS:
            getter = session.get if session is not None else _req.get
            r = getter(url, timeout=timeout, allow_redirects=True, verify=False,
                       headers={"User-Agent": _UA}, stream=True)
            if r.status_code != 200:
                return b""
            chunks, total = [], 0
            for chunk in r.iter_content(65536):
                chunks.append(chunk)
                total += len(chunk)
                if total >= _MAX_BYTES:
                    break
            return b"".join(chunks)
        else:
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if getattr(resp, "status", 200) != 200:
                    return b""
                return resp.read(_MAX_BYTES)
    except Exception:
        return b""


def _fetch_text(url: str, session=None, timeout: int = 10) -> str:
    raw = _fetch(url, session=session, timeout=timeout)
    if not raw:
        return ""
    if url.endswith(".gz"):
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    return raw.decode(errors="replace")


# ── robots.txt parsing ────────────────────────────────────────────────────────

# A "clean" path: starts with /, no regex/wildcard/query characters.
_CLEAN_PATH = re.compile(r'^/[A-Za-z0-9._~%\-/]+$')


def _parse_robots(content: str) -> list:
    """Extract usable Allow/Disallow paths, stored without a leading slash."""
    paths = []
    for line in content.splitlines():
        line = line.strip()
        m = re.match(r'(?:Allow|Disallow):\s*(/\S*)', line, re.I)
        if not m:
            continue
        path = m.group(1).split('?')[0].split('#')[0]
        # Drop globs/regex robots entries like /*.pdf$ or /admin/*
        if any(c in path for c in '*$?'):
            continue
        path = path.rstrip('/')
        if path in ('', '/') or not _CLEAN_PATH.match(path):
            continue
        paths.append(path.lstrip('/'))     # store bare, ffuf-friendly
    return paths


# ── sitemap parsing ───────────────────────────────────────────────────────────

def _sitemap_locs(content: str):
    """
    Return (page_paths, child_sitemaps) from a sitemap or sitemap index.
    page_paths are bare (no leading slash); child_sitemaps are full URLs.
    """
    pages, children = [], []
    is_index = "<sitemapindex" in content.lower()

    def _emit(url: str):
        u = url.strip()
        if not u:
            return
        if is_index:
            children.append(u)
        else:
            p = urlparse(u).path.split('?')[0].split('#')[0].rstrip('/')
            if p and p != '/':
                pages.append(p.lstrip('/'))

    try:
        root = _ET.fromstring(content)
        stripped = re.sub(r'\{[^}]+\}', '',
                          _ET.tostring(root, encoding='unicode'))
        root2 = _ET.fromstring(stripped)
        for loc in root2.iter('loc'):
            _emit(loc.text or "")
    except Exception:
        for m in re.finditer(r'<loc>\s*(https?://[^\s<]+)\s*</loc>', content, re.I):
            _emit(m.group(1))
    return pages, children


def _in_scope(sitemap_url: str, host: str, domain: str) -> bool:
    try:
        net = urlparse(sitemap_url).netloc.lower().split(':')[0]
    except Exception:
        return False
    return net == host.lower() or net == domain.lower() or net.endswith(f".{domain.lower()}")


def _harvest_one(url: str, domain: str, session) -> set:
    """Harvest robots + sitemaps from a single host. Thread-safe (own session)."""
    found = set()
    base = url.rstrip('/')
    host = urlparse(base).netloc.split(':')[0]

    # robots.txt
    content = _fetch_text(f"{base}/robots.txt", session=session)
    if content and re.search(r'user-agent\s*:', content, re.I):
        found.update(_parse_robots(content))
        for m in re.finditer(r'^\s*Sitemap:\s*(\S+)', content, re.I | re.M):
            sm = m.group(1).strip()
            if _in_scope(sm, host, domain):
                _collect_sitemap(sm, host, domain, session, found, depth=0)

    # well-known sitemap locations
    for candidate in (f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"):
        sc = _fetch_text(candidate, session=session)
        if sc and ('<urlset' in sc or '<sitemapindex' in sc):
            pages, children = _sitemap_locs(sc)
            found.update(pages)
            for child in children[:_MAX_INDEX_CHILDREN]:
                if _in_scope(child, host, domain):
                    _collect_sitemap(child, host, domain, session, found, depth=1)
    return found


def _collect_sitemap(url, host, domain, session, found: set, depth: int):
    """Fetch a sitemap URL, add its pages, recurse indexes one level."""
    sc = _fetch_text(url, session=session)
    if not sc:
        return
    pages, children = _sitemap_locs(sc)
    found.update(pages)
    if depth < 1:
        for child in children[:_MAX_INDEX_CHILDREN]:
            if _in_scope(child, host, domain):
                _collect_sitemap(child, host, domain, session, found, depth + 1)


def harvest_robots_and_sitemaps(domain: str, alive_file: Path,
                                 out_dir: Path) -> str:
    """
    Fetch robots.txt + sitemaps from every alive host (in parallel).
    Returns path to extras/web_paths.txt, or "" if nothing was found.
    """
    extras_dir = out_dir / "extras"
    extras_dir.mkdir(exist_ok=True)

    if not alive_file.exists() or alive_file.stat().st_size == 0:
        safe_print("    [i] No alive hosts — skipping robots/sitemap harvest")
        return ""

    with open(alive_file, 'r', errors='replace') as fh:
        urls = [l.strip().split()[0] for l in fh
                if l.strip() and l.strip().split()[0].startswith("http")]
    if not urls:
        return ""

    safe_print(f"    [>] Harvesting robots.txt + sitemaps from {len(urls)} hosts "
               f"(parallel) ...")
    if not _DEFUSED:
        safe_print("    [i] defusedxml not installed — using stdlib XML parser "
                   "(pip install defusedxml recommended)")

    all_paths = set()
    session = _req.Session() if _REQUESTS else None
    if session is not None:
        session.headers.update({"User-Agent": _UA})

    workers = min(_HARVEST_WORKERS, len(urls))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_harvest_one, u, domain, session): u for u in urls}
        for fut in as_completed(futures):
            try:
                all_paths.update(fut.result())
            except Exception:
                pass

    clean = {p for p in all_paths if p and len(p) > 1}
    if not clean:
        safe_print("    [i] No paths found in robots.txt / sitemaps")
        return ""

    web_paths_file = extras_dir / "web_paths.txt"
    count = write_clean(web_paths_file, clean)
    safe_print(f"    [+] Harvested {count} target-specific paths")
    safe_print("    [+] extras/web_paths.txt — prepended to traversal wordlist")
    return str(web_paths_file)


# ── SPF / DMARC / DKIM analysis ──────────────────────────────────────────────

def _analyse_spf(record: str) -> list:
    findings = []
    r = record.lower()

    if '+all' in r:
        findings.append("CRITICAL: SPF uses '+all' — any server can send mail as this domain")
    elif '~all' in r:
        findings.append("WARN: SPF uses '~all' (softfail) — should be '-all' for strict enforcement")
    elif '?all' in r:
        findings.append("WARN: SPF uses '?all' (neutral) — no enforcement")
    elif '-all' in r:
        findings.append("OK: SPF uses '-all' (hardfail)")
    elif 'redirect=' in r:
        # redirect= delegates the policy to another domain — this is valid,
        # not a missing-all misconfiguration.
        findings.append("INFO: SPF uses redirect= — policy delegated to another domain")
    else:
        findings.append("WARN: SPF record has no 'all' mechanism and no redirect=")

    includes = re.findall(r'include:(\S+)', r)
    lookups  = len(includes) + len(re.findall(r'\b(?:a|mx|redirect=|exists:)', r))
    if lookups > 10:
        findings.append(f"WARN: SPF has ~{lookups} DNS-lookup mechanisms — "
                        f"exceeds the RFC 7208 limit of 10 (permerror)")
    if 'ptr' in r:
        findings.append("WARN: SPF uses 'ptr' mechanism — deprecated, slow, unreliable")
    return findings


def _analyse_dmarc(record: str) -> list:
    findings = []
    r = record.lower()

    p_match = re.search(r'\bp=(\w+)', r)
    policy  = p_match.group(1) if p_match else None
    if policy == 'none':
        findings.append("WARN: DMARC p=none — monitoring only, emails can be spoofed without rejection")
    elif policy == 'quarantine':
        findings.append("INFO: DMARC p=quarantine — suspicious mail goes to spam")
    elif policy == 'reject':
        findings.append("OK: DMARC p=reject — strict enforcement")
    else:
        findings.append("WARN: DMARC record missing or invalid 'p' policy")

    pct_match = re.search(r'\bpct=(\d+)', r)
    if pct_match and int(pct_match.group(1)) < 100:
        findings.append(f"INFO: DMARC pct={pct_match.group(1)}% — "
                        f"policy applies to only {pct_match.group(1)}% of mail")

    sp_match = re.search(r'\bsp=(\w+)', r)
    if sp_match and sp_match.group(1) == 'none':
        findings.append("WARN: DMARC sp=none — subdomains have no enforcement")
    return findings


def _parse_dns_records(text: str):
    """Index dns_records.txt into the structures the analysis needs."""
    spf_by_host   = {}   # host -> [spf record, ...]
    dmarc_by_base = {}    # base host -> dmarc record
    dkim_bases    = set()
    mx_hosts      = set()

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        host, typ = parts[0].lower(), parts[1].upper()

        if typ == 'MX':
            mx_hosts.add(host)
        elif typ == 'TXT':
            m = re.search(r'"(.*)"', line)
            val = m.group(1) if m else ""
            low = val.lower()
            if host.startswith('_dmarc.') and 'v=dmarc1' in low:
                dmarc_by_base[host[len('_dmarc.'):]] = val
            elif '._domainkey.' in host and 'v=dkim1' in low:
                dkim_bases.add(host.split('._domainkey.')[-1])
            elif 'v=spf1' in low:
                spf_by_host.setdefault(host, []).append(val)

    return spf_by_host, dmarc_by_base, dkim_bases, mx_hosts


def analyse_email_security(domain: str, out_dir: Path):
    """SPF / DMARC / DKIM analysis from dns_records.txt (no extra network)."""
    extras_dir = out_dir / "extras"
    extras_dir.mkdir(exist_ok=True)

    dns_file = out_dir / "dns_records.txt"
    if not dns_file.exists():
        safe_print("    [i] dns_records.txt not found — skipping email security analysis")
        return

    with open(dns_file, 'r', errors='replace') as fh:
        spf_by_host, dmarc_by_base, dkim_bases, mx_hosts = _parse_dns_records(fh.read())

    findings = []

    # Analyse every SPF record we actually saw (per host).
    for host in sorted(spf_by_host):
        recs = spf_by_host[host]
        if len(recs) > 1:
            findings.append(f"SPF  [{host}]  CRITICAL: {len(recs)} SPF records present "
                            f"— RFC permerror, SPF is ignored by receivers")
        for r in recs:
            for f in _analyse_spf(r):
                findings.append(f"SPF  [{host}]  {f}")

    # Analyse every DMARC record we saw (per host).
    for base in sorted(dmarc_by_base):
        for f in _analyse_dmarc(dmarc_by_base[base]):
            findings.append(f"DMARC [{base}]  {f}")

    # "Missing" only for mail-relevant hosts (apex + anything with MX).
    mail_relevant = {domain.lower()} | mx_hosts
    for host in sorted(mail_relevant):
        if host not in spf_by_host:
            findings.append(f"SPF  [{host}]  MISSING: no SPF record — "
                            f"domain can be used for email spoofing")
        if host not in dmarc_by_base:
            findings.append(f"DMARC [{host}]  MISSING: no DMARC record at _dmarc.{host} "
                            f"— no authentication policy enforced")

    # DKIM (informational — selector-dependent, so absence isn't conclusive).
    if domain.lower() in dkim_bases:
        findings.append(f"DKIM  [{domain}]  OK: DKIM key present for a tested selector")
    else:
        findings.append(f"DKIM  [{domain}]  INFO: no DKIM key found for the tested selectors "
                        f"(a custom selector may still exist)")

    # De-dup while preserving order.
    seen, unique = set(), []
    for f in findings:
        if f not in seen:
            seen.add(f)
            unique.append(f)

    if unique:
        (extras_dir / "email_security.txt").write_text('\n'.join(unique) + '\n')
        safe_print(f"    [+] extras/email_security.txt: {len(unique)} findings")
        for f in unique:
            if 'CRITICAL' in f or ('MISSING' in f and f.startswith('SPF')):
                safe_print(f"    [!] {f}")
    else:
        safe_print("    [i] No email security findings")
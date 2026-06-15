# Recon Raptor 🦅

> Multi-phase subdomain enumeration, DNS resolution, HTTP probing,  
> directory traversal, and IP enrichment — unified in one tool.

```
  ____  ___  __  ___  _  _     ____  __   ____  ____  __  ____ 
 (  _ \(  _)(  )/ __)( \/ )   (  _ \/ _\ (  _ \(_  _)/  \(  _ \
  )   / ) _)  )(( (__  )  (    )   /    \  ) __/  )(  )  / ) __/
 (__\_)(____)(__)\___)(_/\_)  (__\_)\_/\_/(__)   (__) \__/ (__)  
```

---

## What is Recon Raptor?

Recon Raptor chains together the best open-source recon tools into a single automated pipeline. You point it at one domain or a file of many — it runs everything, merges results, removes duplicates, and produces clean output files plus a Markdown summary report per domain.

It is designed to be practical for bug bounty hunters, penetration testers, and security researchers. Every phase is independently toggleable, every tool gracefully degrades if not installed, and the OS-aware installer sets up the full toolchain in one command.

---

## Features

| Phase | What it does | Tools used |
|-------|-------------|------------|
| Subdomain enum | Passive multi-source discovery | subfinder, assetfinder, findomain |
| Subdomain brute | Wordlist-based DNS resolution | puredns + massdns (dnsx fallback) |
| DNS resolution | A, AAAA, CNAME, MX, NS, TXT + zone transfer | dnsx, dig |
| HTTP probe | Live host detection, status codes, titles, tech | httpx |
| Dir traversal | Directory and file discovery on live hosts | gobuster, dirsearch, ffuf |
| IP enrichment | ASN, country, org, CDN detection | ipinfo MMDB / ip-api.com |
| Reporting | Per-domain Markdown summary | built-in |

**Key design decisions:**

- **Single wordlist** — any language, any source. Invalid DNS entries are stripped automatically before use.
- **MMDB-based IP enrichment** — downloads the ipinfo database once, queries locally. No per-IP API calls, no rate limits.
- **Graceful degradation** — missing tools are skipped, not fatal. `recon_raptor check` shows exactly what will run.
- **Clean + raw outputs** — every tool's raw stdout is preserved alongside the deduplicated clean results.
- **Per-domain folders** — structured output, one directory per target.

---

## Requirements

- **Python 3.8+**
- **Linux** — Debian / Ubuntu / Kali / Parrot, RHEL / Fedora / Rocky / AlmaLinux, Arch / Manjaro / BlackArch, Alpine, openSUSE
- **macOS** — with Homebrew installed
- **WSL** — supported, detected automatically and treated as Linux
- `sudo` access is required only for `recon_raptor install`

---

## Quickstart

```bash
# 1. Clone
git clone https://github.com/yourorg/recon_raptor
cd recon_raptor

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Create your config
python3 recon_raptor.py config --init

# 4. Install all recon tools (requires sudo)
sudo python3 recon_raptor.py install --all

# 5. Verify everything is ready
recon_raptor check

# 6. Run your first scan
recon_raptor scan -d example.com -w /path/to/wordlist.txt
```

---

## Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/yourorg/recon_raptor
cd recon_raptor
```

### Step 2 — Install Python dependencies

```bash
pip install -r requirements.txt
```

Dependencies: `requests`, `pyyaml`, `rich`, `maxminddb`

### Step 3 — Create your configuration

```bash
python3 recon_raptor.py config --init
```

This copies `config.default.yaml` to `config.yaml`. Edit `config.yaml` to set your wordlist path and any API tokens. See [Configuration](#configuration) for the full reference.

### Step 4 — Install recon tools

```bash
# Install everything including optional tools
sudo recon_raptor install --all

# Install only required tools (skip screenshots, wayback, vuln scanning)
sudo recon_raptor install --exclude gowitness,gau,nuclei

# Preview every command without running anything (no sudo needed)
recon_raptor install --dry-run
```

The installer:
- Detects your OS and package manager automatically
- Downloads pre-built Go binaries from GitHub Releases — Go does **not** need to be installed
- Creates a symlink at `/usr/local/bin/recon_raptor` so the command works from anywhere
- Prints a clear error with instructions if run without sudo

### Step 5 — Verify

```bash
recon_raptor check
```

This shows which tools are installed, their versions, and the status of your config, wordlist, and resolvers.

---

## Configuration

`config.yaml` is created by `recon_raptor config --init`. It is a deep merge on top of `config.default.yaml` — you only need to set the values you want to change.

```yaml
# ── Required before scanning ──────────────────────────────────────────────
wordlist: /path/to/your/wordlist.txt
# Any language, any source. DNS-invalid entries are stripped automatically.
# Leave empty to skip the bruteforce phase.

# ── Performance ───────────────────────────────────────────────────────────
threads:  50      # concurrent threads across all tools
rate:     150     # max requests per second
timeout:  10      # per-request timeout in seconds
depth:    2       # directory traversal max recursion depth

# ── HTTP ports to probe ───────────────────────────────────────────────────
ports: [80, 443, 8080, 8443]

# ── File extensions for directory traversal ──────────────────────────────
extensions: [php, asp, aspx, html, js, txt, xml, json, bak, zip, env]

# ── Paths ─────────────────────────────────────────────────────────────────
resolvers:  ./resolvers.txt   # DNS resolver list for puredns/massdns
output_dir: ./results         # where domain folders are created

# ── IP enrichment ─────────────────────────────────────────────────────────
tokens:
  ipinfo: "your_token_here"   # see IPInfo MMDB Setup below
mmdb_path: ""                 # leave empty for default location

# ── Phase toggles ─────────────────────────────────────────────────────────
phases:
  passive_enum:  true
  bruteforce:    true
  dns_resolve:   true
  http_probe:    true
  traversal:     true
  ip_enrichment: true

# ── Optional extras ───────────────────────────────────────────────────────
extras:
  zone_transfer:       true   # attempt AXFR against each domain's nameservers
  wayback_urls:        false  # harvest historical URLs via gau
  screenshots:         false  # capture screenshots via gowitness
  subdomain_takeover:  false  # check CNAMEs for dangling services
```

Validate your config at any time:

```bash
recon_raptor config --validate
```

Print the full resolved config (defaults + your overrides):

```bash
recon_raptor config --show
```

---

## IPInfo MMDB Setup

IP enrichment works in two modes.

### Mode 1 — IPInfo MMDB (recommended)

Instead of sending one API request per IP, Recon Raptor downloads the entire ipinfo database as a local MMDB file and queries it instantly for every IP. This means:

- **No rate limits** — look up 10,000 IPs as fast as 1
- **No per-IP network calls** during scans
- **Richer data** — ASN, organisation, country, city, hosting/proxy flags
- **Offline capable** after the initial download

**Setup:**

1. Create a free account at [https://ipinfo.io](https://ipinfo.io) — no credit card required
2. Copy your token from the dashboard
3. Add it to `config.yaml`:

```yaml
tokens:
  ipinfo: "abc123yourtoken"
```

On the first scan that reaches the enrichment phase, Recon Raptor downloads:

```
https://ipinfo.io/data/ipinfo_lite.mmdb?_src=frontend&token=<your_token>
```

The file (~100 MB) is saved next to `config.yaml` as `ipinfo_lite.mmdb` and refreshed automatically every 7 days. You can set a custom path:

```yaml
mmdb_path: /opt/recon_raptor/ipinfo_lite.mmdb
```

### Mode 2 — ip-api.com fallback

If no token is configured, Recon Raptor falls back to ip-api.com. It is completely free with no API key, but rate-limited to approximately 40 requests per minute. Suitable for small IP sets.

---

## Usage

### `recon_raptor scan`

Run the full recon pipeline against one or more targets.

```bash
# Single domain
recon_raptor scan -d example.com

# Multiple domains from a file
recon_raptor scan -D domains.txt

# Bring your own wordlist for this run (overrides config)
recon_raptor scan -d example.com -w /path/to/wordlist.txt

# Write output to a specific directory
recon_raptor scan -d example.com -o /tmp/scan_results

# Use a different config file
recon_raptor scan -d example.com --config /path/to/other_config.yaml
```

**Scan profiles:**

```bash
# Quick — passive enum + HTTP probe only, no bruteforce or traversal
recon_raptor scan -d example.com --quick

# Full — enables extras: wayback URLs, screenshots if tools are installed
recon_raptor scan -d example.com --full
```

**Skip individual phases:**

```bash
recon_raptor scan -d example.com --skip-passive      # skip subfinder/assetfinder/findomain
recon_raptor scan -d example.com --skip-brute        # skip wordlist bruteforce
recon_raptor scan -d example.com --skip-resolve      # skip DNS resolution
recon_raptor scan -d example.com --skip-http         # skip HTTP probing
recon_raptor scan -d example.com --skip-traversal    # skip directory traversal
recon_raptor scan -d example.com --skip-enrich       # skip IP enrichment
```

Flags can be combined:

```bash
# Only subdomain enum + DNS, skip everything after
recon_raptor scan -d example.com --skip-http --skip-traversal --skip-enrich

# Passive enum + probe only, no brute, no traversal
recon_raptor scan -d example.com --skip-brute --skip-traversal --skip-enrich
```

### `recon_raptor check`

Show installed tools, their versions, and the status of your config, wordlist, and resolvers.

```bash
recon_raptor check
```

Example output:

```
  System        Kali Linux 2024.1  ·  x86_64
  Package mgr   apt

  ─── Core enumeration ──────────────────────────────────
  ✓  subfinder       v2.6.3
  ✓  assetfinder     v0.1.1
  ✗  findomain       not found  [required]
  ✓  puredns         v2.1.6
  ✓  massdns         v0.3.0

  ─── Resolution & probing ──────────────────────────────
  ✓  dnsx            v1.1.6
  ✓  httpx           v1.3.7

  ─── Directory traversal ───────────────────────────────
  ✓  gobuster        v3.6.0
  ✗  dirsearch       not found  [optional]
  ✓  ffuf            v2.1.0

  ─── Config & files ────────────────────────────────────
  ✓  config.yaml     found
  ✓  resolvers.txt   28 entries
  ✓  wordlist        42,803 valid entries  (17 DNS-invalid stripped)

  ─── Optional extras ───────────────────────────────────
  ✗  gowitness       not found  [optional]
  ✗  gau             not found  [optional]
  ✗  nuclei          not found  [optional]

  8 ready  ·  5 missing

  To install missing tools:
    sudo recon_raptor install
    sudo recon_raptor install --exclude gowitness,gau,nuclei
    recon_raptor install --dry-run   (preview without sudo)
```

### `recon_raptor install`

Install required and optional tools. **Requires sudo.**

```bash
# Install all tools
sudo recon_raptor install --all

# Install only required tools, skip optional
sudo recon_raptor install

# Skip specific tools
sudo recon_raptor install --exclude gowitness,gau,nuclei

# Preview every command without running anything (no sudo needed)
recon_raptor install --dry-run
```

If you run `install` without sudo, Recon Raptor prints a clear message explaining what it needs and why, and shows you the exact `sudo` command to run. Nothing is silently attempted without root.

The installer handles:

- **Debian / Ubuntu / Kali / Parrot** — `apt`
- **Fedora / RHEL / Rocky / AlmaLinux** — `dnf` / `yum`
- **Arch / Manjaro / BlackArch** — `pacman`
- **Alpine** — `apk`
- **openSUSE** — `zypper`
- **macOS** — `brew`
- **WSL** — detected automatically, treated as its underlying Linux distro

Go-based tools (subfinder, httpx, gobuster, ffuf, etc.) are installed as pre-built binaries downloaded from GitHub Releases. **Go does not need to be installed.**

### `recon_raptor config`

```bash
# Create config.yaml from bundled defaults
recon_raptor config --init

# Print the full resolved configuration
recon_raptor config --show

# Validate config.yaml and report errors or warnings
recon_raptor config --validate
```

---

## Output Structure

For each domain, a folder is created under `output_dir` (default: `./results/`).

```
results/
└── example.com/
    │
    │   ── Subdomains ──────────────────────────────────────
    ├── subdomains.txt          clean unique subdomains
    ├── subdomains_raw.txt      raw output from every tool (untouched)
    │
    │   ── DNS resolution ─────────────────────────────────
    ├── resolved.txt            subdomain → IP pairs (one per line)
    ├── ips.txt                 unique IP addresses only
    ├── dns_records.txt         full A/AAAA/CNAME/MX/NS/TXT dump
    ├── cnames.txt              CNAME chains (review for subdomain takeover)
    │
    │   ── HTTP probing ────────────────────────────────────
    ├── alive.txt               live hosts  URL [status] "title" [tech]
    │
    │   ── Directory traversal ─────────────────────────────
    ├── traversal.txt           discovered paths, all tools merged + deduped
    ├── traversal_raw.txt       raw output from every traversal tool
    │
    │   ── IP enrichment ────────────────────────────────────
    ├── ip_enrichment.json      full JSON record per IP (ASN, country, CDN…)
    ├── ip_summary.txt          human-readable one-liner per IP
    │
    │   ── Report ─────────────────────────────────────────
    └── report.md               auto-generated Markdown summary
```

**`subdomains.txt`** — the primary output of Phase 1. Sorted, lowercase, deduplicated. Contains every subdomain found by passive tools and bruteforce.

**`resolved.txt`** — maps each subdomain to its IP address(es). Format: `subdomain.example.com 1.2.3.4`

**`cnames.txt`** — CNAME records. Format: `sub.example.com -> target.cdn.provider.com`. Review this file for potential subdomain takeover — a CNAME pointing to an unclaimed S3 bucket, GitHub Pages, or Heroku endpoint is a finding.

**`alive.txt`** — output of httpx. Example line:
```
https://api.example.com  [200]  "API Gateway v2"  [nginx, PHP/8.1]
```

**`traversal.txt`** — merged paths from all traversal tools, deduplicated. Example lines:
```
https://example.com/admin  [Status: 200, Size: 4321]
https://example.com/backup.zip  [Status: 200, Size: 102400]
```

**`ip_enrichment.json`** — full enrichment data per IP. Example:
```json
{
  "1.2.3.4": {
    "country": "United States",
    "city": "San Francisco",
    "as": "AS13335 Cloudflare, Inc.",
    "cdn": "Cloudflare",
    "source": "ipinfo_mmdb"
  }
}
```

**`report.md`** — auto-generated summary with a stats table and truncated previews of every output file. Open in any Markdown viewer.

---

## Tool Dependency Reference

| Tool | Role | Required | Install method |
|------|------|----------|---------------|
| subfinder | passive subdomain discovery | yes | GitHub binary |
| assetfinder | passive subdomain discovery | yes | GitHub binary |
| findomain | passive subdomain discovery | no | GitHub binary / brew |
| puredns | DNS bruteforce + wildcard filtering | yes | GitHub binary |
| massdns | DNS resolver backend for puredns | yes | apt / brew / source |
| dnsx | multi-record DNS resolution | yes | GitHub binary |
| httpx | HTTP probing + fingerprinting | yes | GitHub binary |
| gobuster | directory bruteforce | yes | apt / GitHub binary |
| dirsearch | recursive web path scanner | no | pip |
| ffuf | web fuzzer | no | GitHub binary / brew |
| gowitness | screenshot capture | optional | GitHub binary |
| gau | wayback URL harvesting | optional | GitHub binary |
| nuclei | template-based vuln scanning | optional | GitHub binary |

**Required** means the tool covers a phase that has no fallback. The scan will warn and skip the phase, but the output will be incomplete.

**Optional** tools are not installed by `recon_raptor install` by default. Use `--all` to include them.

---

## Resolvers

A starter `resolvers.txt` ships with Recon Raptor containing 20+ well-known public DNS resolvers. For large-scale bruteforce, replace it with a large verified resolver list.

Recommended sources:

- [https://github.com/trickest/resolvers](https://github.com/trickest/resolvers) — 60k+ verified resolvers, updated daily
- [https://github.com/janmasarik/resolvers](https://github.com/janmasarik/resolvers) — community-maintained list

Place the file anywhere and update `resolvers` in `config.yaml`.

---

## Wordlist

Recon Raptor accepts any wordlist in any language. Before scanning, it:

1. Lowercases every entry
2. Strips entries that do not match RFC 1123 DNS label format (`[a-z0-9][a-z0-9-]{0,61}[a-z0-9]`)
3. Deduplicates
4. Reports how many entries were stripped

A minimal bundled wordlist (`wordlists/common.txt`) is included as a fallback. For real scans, use a purpose-built subdomain wordlist:

- [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) — `Discovery/DNS/`
- [https://github.com/assetnote/commonspeak2-wordlists](https://github.com/assetnote/commonspeak2-wordlists)
- [https://github.com/six2dez/OneListForAll](https://github.com/six2dez/OneListForAll)

---

## Common Workflows

### Bug bounty — quick passive recon

```bash
recon_raptor scan -D in_scope_domains.txt --quick -o ./bb_results
```

### Full scan on a single target

```bash
recon_raptor scan -d target.com -w ~/wordlists/subdomains_big.txt --full
```

### Subdomain enum only, no traversal

```bash
recon_raptor scan -d target.com --skip-traversal --skip-enrich
```

### Directory traversal only (subdomains already known)

```bash
# Put known live hosts in a file, then skip everything up to traversal
recon_raptor scan -d target.com --skip-passive --skip-brute \
  --skip-resolve --skip-enrich
# Then manually copy your known hosts into results/target.com/alive.txt
# and re-run with only traversal enabled
```

### Multi-domain scan with custom output path

```bash
recon_raptor scan -D clients.txt -o /mnt/pentest_drive/results
```

---

## Project Structure

```
recon_raptor/
├── recon_raptor.py              entry point  (chmod +x, symlinked to PATH)
├── config.default.yaml          bundled defaults — never edit this file
├── config.yaml                  your config — created by config --init
├── requirements.txt
├── resolvers.txt                bundled starter DNS resolver list
├── ipinfo_lite.mmdb             downloaded on first enrichment run (if token set)
│
├── wordlists/
│   └── common.txt               minimal bundled fallback wordlist
│
└── modules/
    ├── core/
    │   ├── config.py            config loader + validator
    │   ├── preflight.py         tool detection + capability table
    │   ├── installer.py         OS-aware tool installer
    │   ├── scanner.py           scan orchestrator
    │   └── reporter.py          Markdown report generator
    │
    ├── phases/
    │   ├── subdomain.py         passive enum + bruteforce
    │   ├── resolver.py          DNS resolution + zone transfer
    │   ├── http_probe.py        HTTP probing via httpx
    │   ├── traversal.py         directory traversal
    │   └── enrichment.py        IP enrichment (MMDB + ip-api.com)
    │
    └── utils/
        ├── wordlist.py          wordlist cleaner + validator
        ├── output.py            file writers + subdomain extractor
        └── network.py           HTTP helpers for enrichment APIs
```

---

## Contributing

Contributions are welcome. Please open an issue before submitting a large pull request so we can discuss the change first.

**Areas actively looking for contributions:**

- `modules/phases/extras.py` — `gau` wayback harvesting, `gowitness` screenshots, `nuclei` scanning
- `modules/phases/takeover.py` — CNAME dangling check against `cnames.txt`
- More OS support in `installer.py`
- Additional CDN/cloud ASN mappings in `enrichment.py`
- Test coverage

**Code style:**

- Python 3.8+ compatible (avoid walrus operator, `match`, etc. where possible for compatibility)
- Type hints on all public functions
- Docstring on every module and public function
- No new third-party dependencies without discussion

---

## Legal Disclaimer

Recon Raptor is intended for **authorised security testing only**.

Only run this tool against systems you own, have explicit written permission to test, or that are listed in a bug bounty programme's in-scope assets. Unauthorised scanning is illegal in most jurisdictions and violates the terms of service of virtually every platform.

The authors accept no liability for misuse or any damage caused by this tool.

---

## License

MIT License — see [LICENSE](LICENSE) for full text.

---

*Built for the security community — use responsibly.*

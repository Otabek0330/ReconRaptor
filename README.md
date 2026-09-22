# Recon Raptor

```
      ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
      ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
      ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝

      ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗
      ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
      ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
      ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗
      ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║
      ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

> Multi-phase subdomain enumeration · DNS resolution · Port scanning
> HTTP probing · Directory traversal · IP enrichment — unified in one tool.

---

## What is Recon Raptor?

Recon Raptor chains together the best open-source recon tools into a single automated pipeline. Point it at one domain or a file of many — it runs everything, merges results, removes duplicates, and produces clean output files plus a Markdown summary report per domain.

Designed for bug bounty hunters, penetration testers, and security researchers. Every phase is independently toggleable, every tool degrades gracefully if not installed, and the installer sets up the entire toolchain — including Go itself — with one command.

---

## Features

| Phase | What it does | Tools used |
|-------|-------------|------------|
| Subdomain enum | Passive multi-source + crt.sh, in parallel (crt.sh always runs, even with no CLI tools) | subfinder, assetfinder, findomain, crt.sh |
| Subdomain brute | Wordlist DNS resolution, wildcard-aware, live progress | puredns + massdns (dnsx fallback) |
| DNS resolution | A, AAAA, CNAME, MX, NS, TXT + `_dmarc` / DKIM records + zone transfer | dnsx, dig |
| Port scanning | Fast port scan on **public** IPs (private/loopback excluded) | naabu |
| HTTP probe | Live host detection; per-host ports from the port scan; apex always included | httpx |
| Dir traversal | One primary tool by default (all three optional), soft-404 aware | ffuf / gobuster / dirsearch |
| Web path harvest | robots.txt + in-scope sitemap paths (parallel) | built-in |
| IP enrichment | ASN, country, org, **CDN vs cloud-hosting** classification | ipinfo MMDB / ip-api.com |
| Email security | Per-host SPF, DMARC, DKIM analysis (incl. `_dmarc` + common selectors) | built-in |
| Reporting | Per-domain Markdown incl. CDN/cloud split + internal-IP exposure | built-in |

**Key design decisions:**

- **Two separate wordlists** — subdomain wordlist (`-w`) and directory traversal wordlist (`-dw`) are completely different data sets.
- **Apex domain always included** — every phase after enumeration probes the apex domain itself, not just discovered subdomains (`subdomains.txt` stays a pure enumeration artifact; the actual target list is `resolve_targets.txt`).
- **Go installed automatically** — the installer installs Go from go.dev, then uses `go install` as the primary method for every Go-based tool (before the package manager).
- **Verified installs** — downloaded binaries are SHA-256 verified against the release's checksums; the Go tarball is verified against go.dev's published hash. A mismatch aborts the install; when a project publishes no checksum the install proceeds but says so explicitly.
- **Fingerprinted checkpoint / resume** — interrupted scans resume, but a phase is only cached when it actually succeeded *and* had its required tool. Changing a flag, wordlist, or tool set re-runs the affected phase instead of silently reusing a stale result.
- **CDN vs cloud** — Cloudflare/Fastly/Akamai/CloudFront (origin masked) are reported separately from cloud hosting (AWS/GCP/Azure/DO — origin likely reachable).
- **Private IP filtering** — RFC 1918 / loopback addresses are excluded from scanning and enrichment, and surfaced as an internal-exposure finding (`ips_private.txt`).
- **Single primary traversal tool by default** — running gobuster + dirsearch + ffuf together roughly triples the request volume for near-identical results; set `traversal_all_tools: true` to run all three.
- **Thread-safe output** — parallel phases write to the console without interleaving.

---

## Requirements

- **Python 3.9+** (uses standard-library generic type hints)
- **Linux** — Debian / Ubuntu / Kali / Parrot, RHEL / Fedora / Rocky / AlmaLinux, Arch / Manjaro / BlackArch, Alpine, openSUSE
- **macOS** — with Homebrew installed
- **WSL** — detected automatically, treated as Linux
- `sudo` access for initial tool installation (Go itself is installed automatically — no pre-existing Go required)

Python dependencies: `requests`, `pyyaml`, `rich`, `maxminddb`, `defusedxml`.

---

## Quickstart

```bash
# 1. Clone
git clone https://github.com/Otabek0330/ReconRaptor
cd ReconRaptor

# 2. Python dependencies
pip install -r requirements.txt

# 3. Create your config
python3 recon_raptor.py config --init

# 4. Get a large resolver list (the bundled one is a small starter set —
#    see "Resolver List" below for why this matters a lot)
curl -o resolvers.txt https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt

# 5. Install Go + all recon tools (one command, -E preserves your env)
sudo -E python3 recon_raptor.py install --all

# 6. Open a new terminal (picks up Go PATH), then verify
recon_raptor check

# 7. Run your first scan
recon_raptor scan -d example.com \
  -w /path/to/subdomain_wordlist.txt \
  -dw /path/to/directory_wordlist.txt
```

---

## Installation

### Step 1 — Clone

```bash
git clone https://github.com/Otabek0330/ReconRaptor
cd ReconRaptor
```

### Step 2 — Python dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Create your config

```bash
python3 recon_raptor.py config --init
```

This copies `config.default.yaml` to `config.yaml`. Edit it to set your wordlist paths and API tokens.

### Step 4 — Install all tools

```bash
sudo -E recon_raptor install --all
```

> **Why `-E`?** It preserves your shell environment (including `GITHUB_TOKEN`) through the `sudo` call. Plain `sudo` resets the environment by default on Debian/Kali, silently stripping exported variables. `-E` is the fix. (If you run `recon_raptor install` without typing `sudo` yourself, the script re-executes itself as `sudo -E` automatically.)

The installer:
1. **Installs Go** from `https://go.dev` if not already present (1.21+ required), verifying the tarball against go.dev's published SHA-256 and swapping it into place atomically.
2. Uses `go install` as the **primary** method for every Go-based tool — before the package manager, so you don't get an old `apt` build shadowing a fresh one.
3. **Verifies** each binary landed in `/usr/local/bin` (recovering from `$GOPATH/bin` if needed) before reporting success.
4. Falls back to a **SHA-256-verified** GitHub binary download (fail-closed on mismatch) when `go install` isn't applicable (e.g. `findomain`, a Rust binary).
5. Builds `massdns` from source as a last resort, in a private temp directory.
6. Creates a `recon_raptor` symlink in `/usr/local/bin`.

```bash
# Everything including optional tools
sudo -E recon_raptor install --all

# Skip optional tools
sudo -E recon_raptor install --exclude gowitness,gau,nuclei

# Preview every command without running anything (no sudo needed)
recon_raptor install --dry-run
```

> **Open a new terminal after install** to pick up the Go PATH (`/usr/local/go/bin`).

**Install-time environment variables:**

| Variable | Effect |
|----------|--------|
| `GITHUB_TOKEN` | Raises the GitHub API limit for the binary fallback (60 → 5000 req/hr). |
| `RR_INSTALL_LATEST=1` | Force `@latest` for all Go tools (otherwise any pins set in the installer are used). |
| `RR_GO_NOSUMDB=1` | Disable Go's checksum-DB verification (only for proxied/air-gapped networks; on by default). |

> **macOS note:** Homebrew refuses to run as root, so under `sudo` on macOS the brew steps are skipped in favour of `go install` / source builds. Binaries still land in `/usr/local/bin`.

### Step 5 — Resolver list

`resolvers.txt` ships with ~44 well-known, generally reliable public resolvers — curated for reliability, not scraped in bulk. This is intentional: `massdns`/`puredns` retry every resolver that doesn't respond, so a list with thousands of dead or rate-limited entries can be **slower** than a small list where every resolver actually works.

If you need more throughput for a very large wordlist, **validate a bigger list first** rather than using it raw:

```bash
pip install dnsvalidator
dnsvalidator -tL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
  -threads 100 -o resolvers_validated.txt
```

Then point `resolvers:` in `config.yaml` at the validated output. A relative `resolvers:` path is resolved against the project root, so the tool works when launched from any directory via the PATH symlink.

### Step 6 — Verify

```bash
recon_raptor check
```

Shows every tool's resolved path — flagging anything not in `/usr/local/bin` / `/usr/local/sbin` / `/opt/homebrew/bin` with a `⚠`. It also warns if the `httpx` on your PATH doesn't look like ProjectDiscovery's (the `python3-httpx` package can shadow it on Kali/Debian, which would make the HTTP probe return 0 live hosts).

---

## GitHub Token (optional, but recommended)

`go install` — the primary install method — does **not** need a GitHub token; it uses Go's module proxy.

A token only matters for the **binary download fallback** (e.g. `findomain`), which calls the GitHub API, capped at 60 requests/hour anonymously.

**Get a free token (60 seconds, no scopes needed):** https://github.com/settings/tokens/new — leave every scope unchecked (public repo access needs none).

**Use it correctly:**

```bash
# Option A — preserve your whole environment through sudo
export GITHUB_TOKEN=ghp_your_token_here
sudo -E python3 recon_raptor.py install --all

# Option B — pass just this one variable explicitly (note: no '$' before the literal token)
sudo GITHUB_TOKEN=ghp_your_token_here python3 recon_raptor.py install --all
```

Plain `sudo` (without `-E` and without passing the variable) strips it before the script starts.

---

## Configuration

`config.yaml` is created by `recon_raptor config --init`. You only need to set values you want to change — everything else uses defaults.

```yaml
# ── Wordlists (TWO SEPARATE FILES) ────────────────────────────
wordlist:     ""      # subdomain labels: "api", "dev", "mail"   (-w)
dir_wordlist: ""      # web paths:        "admin", ".env"        (-dw)

# ── Performance ───────────────────────────────────────────────
threads:        50    # HTTP probe + traversal concurrency
brute_threads:  500   # DNS bruteforce/resolution threads (dnsx path)
rate:           150   # max requests/sec for ffuf traversal
timeout:        10    # per-request timeout (seconds)
depth:          2     # directory traversal recursion depth
traversal_jobs: 3     # alive hosts scanned in parallel

# Run gobuster + dirsearch + ffuf together (default: one primary tool)
traversal_all_tools: false

# ── HTTP ports (fallback when no port scan data) ──────────────
ports: [80, 443, 8080, 8443]

# ── Port scanning (naabu) ─────────────────────────────────────
port_scan:
  top_ports: 1000
  rate:      1000
  # ports: [80, 443, 8080]   # optional: exact ports instead of top_ports

# ── Directory traversal extensions (first 8 are used) ─────────
extensions: [php, asp, aspx, html, js, json, bak, zip, env, config, sql]

# ── Paths ─────────────────────────────────────────────────────
resolvers:  ./resolvers.txt
output_dir: ./results
# mmdb_path: ./ipinfo_lite.mmdb   # optional override

# ── API tokens (all optional) ─────────────────────────────────
tokens:
  ipinfo: ""

# ── Phase toggles ─────────────────────────────────────────────
phases:
  passive_enum:   true
  bruteforce:     true
  dns_resolve:    true
  port_scan:      true
  http_probe:     true
  traversal:      true
  ip_enrichment:  true
  harvest:        true    # robots.txt + sitemap harvesting
  email_security: true    # SPF / DMARC / DKIM analysis

# ── Optional extras ───────────────────────────────────────────
extras:
  zone_transfer:       true
  wayback_urls:        false   # not wired yet
  screenshots:         false   # not wired yet
  subdomain_takeover:  false   # not wired yet
```

Validate or print at any time (banner goes to stderr, so `--show` output is pipeable):

```bash
recon_raptor config --validate
recon_raptor config --show
recon_raptor config --show --config /path/to/other.yaml
```

---

## IPInfo MMDB Setup

Instead of one API call per IP, Recon Raptor can download the entire ipinfo database and query it locally.

**Benefits:** No rate limits · millisecond lookups · works offline after download · richer data

1. Create a free account at [https://ipinfo.io](https://ipinfo.io)
2. Add your token to `config.yaml` under `tokens.ipinfo`

On first enrichment run, Recon Raptor downloads `ipinfo_lite.mmdb` (~100 MB) **atomically** (to a `.part` file, then swapped into place, so a failed download never corrupts an existing database) and refreshes it every 7 days. Without a token, `ip-api.com` is used as a free fallback (rate-limit aware, batched 100 IPs/request). Tokens are masked in all log output.

---

## Usage

### `recon_raptor scan`

```bash
# Single domain — passive enum only (no wordlists)
recon_raptor scan -d example.com

# Full scan with both wordlists
recon_raptor scan -d example.com -w ~/subs.txt -dw ~/dirs.txt

# Multiple domains from file
recon_raptor scan -D targets.txt -w subs.txt -dw dirs.txt

# Fast mode — passive enum + HTTP probe only
recon_raptor scan -d example.com --quick

# Full mode — enables optional extras
recon_raptor scan -d example.com -w subs.txt -dw dirs.txt --full

# Custom output folder / config
recon_raptor scan -d example.com -o /tmp/results --config my.yaml

# Skip specific phases
recon_raptor scan -d example.com --skip-ports
recon_raptor scan -d example.com --skip-traversal --skip-enrich
recon_raptor scan -d example.com --skip-passive --skip-brute   # DNS-only mode

# Ignore any checkpoint and re-run everything from scratch
recon_raptor scan -d example.com --fresh
```

Targets are validated: schemes/paths/ports are stripped or rejected, IP literals and single-label names (`localhost`, `com`) are rejected, and internationalised domains are accepted (converted to punycode).

**Resume:** re-running the same command skips phases that completed successfully. A phase that failed, ran without its required tool, or whose inputs (flags, wordlist, tool set) changed is automatically re-run — you won't silently inherit a stale or empty result.

### `recon_raptor check`

Shows every installed tool, its version, and its resolved path (flagging anything outside the known install dirs), plus config status, wordlist stats, and an httpx-identity warning if the wrong `httpx` is on PATH.

### `recon_raptor install`

```bash
sudo -E recon_raptor install --all                    # everything, env preserved
sudo -E recon_raptor install                          # required tools only
sudo -E recon_raptor install --exclude gowitness,gau  # skip specific tools
recon_raptor install --dry-run                        # preview, no sudo needed
```

### `recon_raptor config`

```bash
recon_raptor config --init        # create config.yaml from defaults
recon_raptor config --show        # print effective config (pipeable)
recon_raptor config --validate    # check for errors
```

---

## Output Structure

```
results/
└── example.com/
    │   ── Subdomains ──────────────────────────────────────────
    ├── subdomains.txt          clean unique subdomains (apex excluded)
    ├── subdomains_raw.txt      raw output from all tools
    ├── resolve_targets.txt     subdomains.txt + apex — the list every
    │                           phase below actually uses
    │
    │   ── DNS resolution ─────────────────────────────────────
    ├── resolved.txt            target → IP pairs
    ├── ips.txt                 unique public IPs
    ├── ips_public.txt          public IPs sent to the port scanner
    ├── ips_private.txt         RFC 1918 / loopback IPs ← internal exposure
    ├── dns_records.txt         A/AAAA/CNAME/MX/NS/TXT + _dmarc/DKIM
    ├── cnames.txt              CNAME chains ← review for takeover
    │
    │   ── Port scanning ──────────────────────────────────────
    ├── open_ports.txt          IP:PORT pairs
    ├── ports.json              {IP: [port, ...]} mapping
    │
    │   ── HTTP probing ────────────────────────────────────────
    ├── alive.txt               URL  [status]  "title"  [tech]
    │
    │   ── Directory traversal ────────────────────────────────
    ├── traversal.txt           discovered paths (case-sensitive dedup)
    ├── traversal_raw.txt       raw tool output
    │
    │   ── IP enrichment ───────────────────────────────────────
    ├── ip_enrichment.json      full JSON per IP (incl. cdn / cloud)
    ├── ip_summary.txt          one-liner per IP
    │
    │   ── Extras ─────────────────────────────────────────────
    ├── extras/
    │   ├── web_paths.txt       paths from robots.txt + sitemaps
    │   └── email_security.txt  per-host SPF / DMARC / DKIM findings
    │
    ├── .rr_checkpoint.json     resume state (fingerprinted, hidden)
    └── report.md               auto-generated Markdown summary
```

The report includes a CDN-vs-cloud breakdown and an "Internal IP Exposure" section whenever private addresses appear in a target's public DNS.

---

## Tool Dependency Reference

| Tool | Role | Required | Install method |
|------|------|----------|----------------|
| subfinder | passive subdomain discovery | yes | `go install` |
| assetfinder | passive subdomain discovery | yes | `go install` |
| findomain | passive subdomain discovery | no | GitHub binary (SHA-verified) |
| puredns | DNS bruteforce + wildcard filtering | yes | `go install` |
| massdns | DNS resolver backend for puredns | yes | apt / build from source |
| dnsx | multi-record DNS resolution | yes | `go install` |
| httpx | HTTP probing + fingerprinting | yes | `go install` |
| naabu | fast port scanner | no | `go install` |
| gobuster | directory bruteforce | yes | `go install` |
| dirsearch | recursive web path scanner | no | pipx / pip / git |
| ffuf | web fuzzer (default traversal tool) | no | `go install` |
| gowitness | screenshot capture | optional | `go install` |
| gau | wayback URL harvesting | optional | `go install` |
| nuclei | template-based vuln scanning | optional | `go install` |
| dig | zone transfer (AXFR) | optional | dnsutils / bind-tools |

> Go is installed automatically by `sudo -E recon_raptor install`.

---

## Wordlist Recommendations

**Subdomain wordlists** (`-w`): [SecLists/Discovery/DNS](https://github.com/danielmiessler/SecLists), [commonspeak2](https://github.com/assetnote/commonspeak2-wordlists), [OneListForAll](https://github.com/six2dez/OneListForAll)

**Directory wordlists** (`-dw`): [SecLists/Discovery/Web-Content](https://github.com/danielmiessler/SecLists), [assetnote/wordlists](https://wordlists.assetnote.io)

**Resolver lists**: [dnsvalidator](https://github.com/vortexau/dnsvalidator) + [trickest/resolvers](https://github.com/trickest/resolvers) — always validate before use.

---

## Common Workflows

```bash
# Bug bounty — quick passive recon
recon_raptor scan -D in_scope.txt --quick

# Full scan, all phases
recon_raptor scan -d target.com -w subs_big.txt -dw raft-medium.txt --full

# Maximum traversal coverage (run all three tools)
# → set traversal_all_tools: true in config.yaml, then:
recon_raptor scan -d target.com -dw dirs.txt --skip-passive --skip-brute

# Multi-domain with resume — re-run the same command after an interruption
recon_raptor scan -D clients.txt -w subs.txt -dw dirs.txt
```

---

## Project Structure

```
ReconRaptor/
├── recon_raptor.py              entry point (symlinked to PATH)
├── config.default.yaml          bundled defaults — never edit directly
├── config.yaml                  your config — created by config --init
├── requirements.txt             requests, pyyaml, rich, maxminddb, defusedxml
├── resolvers.txt                bundled DNS resolver starter list
├── wordlists/common.txt         minimal bundled fallback
│
└── modules/
    ├── core/
    │   ├── config.py            config loader + strict FQDN/IDN validator
    │   ├── preflight.py         parallel tool detection + capability table
    │   ├── installer.py         verified, OS-aware installer (Go + tools)
    │   ├── scanner.py           orchestrator + fingerprinted checkpoints
    │   └── reporter.py          Markdown report (CDN/cloud + exposure)
    │
    ├── phases/
    │   ├── subdomain.py         passive + crt.sh (always) + wildcard brute
    │   ├── resolver.py          DNS resolution + _dmarc/DKIM + zone transfer
    │   ├── port_scanner.py      naabu (public IPs only)
    │   ├── http_probe.py        httpx (per-host ports + apex)
    │   ├── traversal.py         single primary tool by default, soft-404 aware
    │   ├── enrichment.py        CDN vs cloud classification
    │   └── extras.py            robots/sitemap harvest + per-host SPF/DMARC/DKIM
    │
    └── utils/
        ├── process.py           subprocess runner (path resolution, group kill)
        ├── wordlist.py          subdomain + dir wordlist cleaners
        ├── output.py            thread-safe printing + strict subdomain extract
        └── network.py           HTTP helpers + atomic download + ip-api batch
```

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'modules...'`**
A file is missing from your local copy — make sure the whole tree is committed. To find gaps in one pass:

```bash
python3 -c "
import ast, pathlib
missing = []
for f in pathlib.Path('.').rglob('*.py'):
    if '__pycache__' in str(f): continue
    for node in ast.walk(ast.parse(f.read_text())):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('modules.'):
            p = pathlib.Path(node.module.replace('.', '/') + '.py')
            if not p.exists(): missing.append((str(f), node.module))
print('All imports resolve.' if not missing else missing)
"
```

**HTTP probe / `alive.txt` comes back empty**
Check `recon_raptor check` for the httpx warning — on Kali/Debian the `python3-httpx` package can shadow ProjectDiscovery's httpx. Reinstall it: `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`. (The probe now refuses to cache an empty result caused by the wrong binary, so a re-run works once httpx is fixed.)

**A phase keeps returning 0 results**
Zero-result phases are **not** cached, so simply re-running retries them. Check `subdomains_raw.txt` for tool errors and confirm network access. Use `--fresh` to force a full clean run.

**`puredns` bruteforce seems slow**
Check your resolver count (`wc -l resolvers.txt`). A tiny list against a 100k+ wordlist is genuinely slow — see [Step 5](#step-5--resolver-list). Live progress streams so a "frozen" terminal usually just means it's still working.

**A tool shows installed under plain `sudo` but not when run directly**
`/usr/local/bin` may not be in sudo's `secure_path`. Recon Raptor resolves tool paths directly at both detection and execution time, so scans work regardless — but plain `sudo <tool>` won't. Fix with `sudo visudo` → add `/usr/local/bin` to `secure_path`.

---

## Security Notes

- `config.yaml` is excluded from git via `.gitignore` — it may contain your ipinfo token.
- Downloaded binaries are **SHA-256 verified** (fail-closed on mismatch); the Go tarball is verified against go.dev's published hash. Unverifiable downloads are installed but clearly labelled.
- Archives are extracted with path-traversal protection (no tar-/zip-slip), even as root.
- Go is installed **atomically** and its checksum DB (`GOSUMDB`) stays enabled by default.
- API tokens (ipinfo, GitHub) are masked in all log output.
- Private / loopback IPs are excluded from scanning and enrichment, and surfaced as an internal-exposure finding.
- All subprocess calls use `shell=False`; child process groups are killed on Ctrl+C or timeout.

---

## Contributing

Contributions welcome. Open an issue before a large PR.

**High-priority areas:**
- `takeover.py` — dangling-CNAME takeover check against `cnames.txt` (data is ready).
- Wildcard-aware filtering of **passive** results (must keep dangling-CNAME candidates).
- Wire `gau` (wayback) and `gowitness` (screenshots) — config toggles exist, code doesn't yet.
- DNS permutations (alterx / dnsgen) through `puredns resolve`.
- Test coverage — parsers (httpx, robots, sitemap, SPF/DMARC, dirsearch/gobuster) are the highest-value targets.

**Code style:** Python 3.9+ · type hints on public functions · docstring on every module.

---

## Legal Disclaimer

Recon Raptor is intended for **authorised security testing only**. Only run it against systems you own or have explicit written permission to test. Unauthorised scanning is illegal in most jurisdictions. The authors accept no liability for misuse.

---

## License

MIT License. (Add a `LICENSE` file to the repo to make the terms explicit.)

---

*Built for the security community — use responsibly.*
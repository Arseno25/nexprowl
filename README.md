<div align="center">

<img src="assets/logo.svg" width="700" alt="dscan logo"/>

<p>
  <img src="https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white&style=flat" alt="Go 1.24"/>
  <img src="https://img.shields.io/badge/License-MIT-22c55e?style=flat" alt="MIT License"/>
  <img src="https://img.shields.io/badge/PRs-Welcome-22c55e?style=flat" alt="PRs Welcome"/>
  <img src="https://img.shields.io/badge/Built%20by-shadow0x0-a855f7?style=flat" alt="shadow0x0"/>
</p>

</div>

---

## Quick Install

### Clone & Build (Go required)

```bash
git clone https://github.com/Arseno25/dscan.git
cd dscan
go build -ldflags="-s -w" -o dscan .
sudo mv dscan /usr/local/bin/   # Linux/macOS, or keep it local
```

### Download pre-built binary

Grab the right binary from [`bin/`](bin/) for your platform, then:

**Windows:**
```powershell
.\dscan-windows-amd64.exe example.com
```

**Linux:**
```bash
chmod +x bin/dscan-linux-amd64
./bin/dscan-linux-amd64 example.com
```

**macOS:**
```bash
chmod +x bin/dscan-darwin-arm64   # Apple Silicon
./bin/dscan-darwin-arm64 example.com
```

---

## Features

| Module | Capabilities |
|--------|--------------|
| `dns` | Parallel A/AAAA/MX/NS/TXT/CNAME lookups · null-MX aware · wildcard DNS detection · **AXFR zone transfer** (raw DNS wire protocol, automatic hostname extraction) |
| `sub` | 5 keyless passive sources (crt.sh, CertSpotter, OTX, HackerTarget, Anubis) · 330-word bruteforce · wildcard filtering · CNAME resolution |
| `ports` | Worker-pool TCP connect scan · service naming · **banner grabbing** (SSH/FTP/MySQL/Redis/...) |
| `http` | HTTPS→HTTP probing of the target **+ every live subdomain** · status/title/server/redirect · 70 tech signatures · passive **+ active** WAF detection |
| `vhost` | Hidden virtual host discovery · Host-header + **SNI fuzzing** · wildcard-noise size-model filter |
| `tls` | TLS version · cipher · issuer · **expired-cert flagging** · SANs extraction |
| `takeover` | Dangling CNAME detection · 50 claimable-service fingerprints · NXDOMAIN verification |

Extras: **custom DNS resolvers** (`-r`, round-robin) · **per-target rate limiting** (`-rate`) · JSON/JSONL/CSV/Markdown/TXT output · modern animated UI · concurrent multi-target batch mode.

## Usage

```bash
# Full help
dscan --help

# Full scan, single target (all modules + animated UI)
dscan example.com

# Batch — 10 concurrent targets, per-target files + summary.csv
dscan -l targets.txt -T 10 -o results/

# Subdomains + HTTP only, 500 workers
dscan example.com -m sub,http -t 500

# Wide port scan
dscan example.com -p 1-10000 -t 1000

# DNS records + zone transfer attempt
dscan example.com -m dns

# Hunt hidden virtual hosts
dscan example.com -m dns,vhost

# Stealth: custom resolvers + 50 ops/s rate limit
dscan example.com -r resolvers.txt -rate 50

# Passive only, pipe-ready for jq/nuclei
dscan -l targets.txt -passive -silent -o subs.jsonl

# Markdown report for bug bounty notes
dscan -l targets.txt -o report.md
```

### `targets.txt` format

```
# comments with #
example.com
target.co.id
https://sub.domain.com/path   ← normalized to sub.domain.com
```

### `resolvers.txt` format

```
8.8.8.8
1.1.1.1
9.9.9.9
1.0.0.1:53
```

## Output

`-o` auto-detects the mode from the path:

| Path | Result |
|------|--------|
| `out.json` | Combined pretty JSON |
| `out.jsonl` | JSONL — one result per line, pipe-ready for `jq`/`nuclei` |
| `out.csv` | Flattened CSV (target, host, status, tech, waf, ports) |
| `out.md` | Markdown report with per-target tables |
| `out.txt` | Plain-text summary |
| `results/` | **Directory mode**: `results/<target>.json` + `summary.csv` |

Format override: `-format json|jsonl|csv|md|txt`.

## Flag Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-l` | — | target list file |
| `-m` | all | modules: `dns,sub,ports,http,vhost,tls,takeover` |
| `-p` | `top100` | ports: `top100` · `full` · `80,443` · `1-1024` |
| `-t` | 300 | workers per module |
| `-T` | 5 | concurrent targets (batch) |
| `-timeout` | 4 | network timeout (seconds) |
| `-w` | built-in | custom subdomain wordlist |
| `-r` | system DNS | DNS resolvers file (round-robin) |
| `-rate` | 0 (∞) | max ops/sec per target |
| `-passive` | false | skip bruteforce |
| `-probe-subs` | true | HTTP-probe discovered subdomains |
| `-o` / `-format` | — | output path & format |
| `-silent` | false | no UI, one line per target |
| `-no-color` | false | disable colors |
| `-h`, `--help` | — | full help |
| `-version` | — | print version |

---

<div align="center">
developed by <b>shadow0x0</b> · for authorized security testing & bug bounty
</div>

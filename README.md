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
| `dns` | A/AAAA/MX/NS/TXT/CAA/SOA/SRV/PTR · SPF/DMARC · ASN ownership · null-MX · **AXFR** |
| `sub` | 5 keyless + optional keyed passive sources · TLS SANs · bruteforce · wildcard filtering |
| `ports` | Multi-host/IP TCP connect scan · service naming · **banner grabbing** |
| `http` | Port-aware HTTP/HTTPS probing · hashes · response timing · tech/WAF/CDN detection |
| `vhost` | Hidden virtual host discovery · Host-header + **SNI fuzzing** · wildcard-noise size-model filter |
| `tls` | Multi-endpoint TLS · cipher · issuer · expiry · hostname mismatch · SAN feedback |
| `takeover` | Dangling CNAME detection · 48 claimable-service fingerprints · NXDOMAIN **+ unclaimed-page body verification** (catches GitHub Pages / Shopify / Heroku, which keep resolving) |
| `crawl` | Bounded same-scope HTML/JS/robots/sitemap endpoint discovery |

Extras: run history + `dscan diff` · STDIN/`-emit` pipelines · screenshots via system Chrome · webhook notifications · custom resolvers · rate limiting · JSON/JSONL/CSV/Markdown/HTML/TXT.

## Usage

```bash
# Full help
dscan --help

# Full scan, single target (all modules + animated UI)
dscan example.com

# Batch — 10 concurrent targets, automatically saved to results/
dscan -l targets.txt -T 10

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
dscan -l targets.txt -passive -silent -o results/subs.jsonl

# Markdown report for bug bounty notes
dscan -l targets.txt -o results/report.md
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

Every directory-mode scan gets an immutable timestamped run under `results/`.
Each run contains per-target JSON, summary CSV, HTML, manifest, and plain asset lists.
`results/latest.txt` points to the newest run.

| Path | Result |
|------|--------|
| `results/out.json` | Combined pretty JSON |
| `results/out.jsonl` | JSONL — one result per line, pipe-ready for `jq`/`nuclei` |
| `results/out.csv` | Flattened CSV (target, host, status, tech, waf, ports) |
| `results/out.md` | Markdown report with per-target tables |
| `results/out.html` | Responsive standalone HTML report |
| `results/out.txt` | Plain-text summary |
| `results/` | **Run history**: `results/<timestamp>/...` + `latest.txt` |

Format override: `-format json|jsonl|csv|md|html|txt`.

Compare two runs (exit code `3` means changes were found):

```bash
dscan diff -o results/diff.json results/OLD results/NEW
```

Pipeline mode:

```bash
cat domains.txt | dscan -silent -emit urls
dscan example.com -emit endpoints
```

Optional passive provider keys:

```bash
export DSCAN_SECURITYTRAILS_KEY=...
export DSCAN_VIRUSTOTAL_KEY=...
export DSCAN_SHODAN_KEY=...
```

## Flag Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-l` | — | target list file |
| `-m` | all | modules: `dns,sub,ports,http,vhost,tls,takeover,crawl` |
| `-p` | `top100` | ports: `top100` · `full` · `80,443` · `1-1024` |
| `-t` | 300 | workers per module |
| `-T` | 5 | concurrent targets (batch) |
| `-timeout` | 4 | network timeout (seconds) |
| `-w` | built-in | custom subdomain wordlist |
| `-r` | system DNS | DNS resolvers file (round-robin) |
| `-rate` | 0 (∞) | max ops/sec per target |
| `-passive` | false | skip bruteforce |
| `-probe-subs` | true | HTTP-probe discovered subdomains |
| `-scan-all-ips` | false | scan all IPv4/IPv6 addresses |
| `-ports-subs` | false | port-scan discovered subdomains |
| `-probe-both` | false | probe both HTTP and HTTPS |
| `-active` | false | enable intrusive active probes |
| `-include` / `-exclude` | — | scope additions and exclusions |
| `-crawl-depth` / `-crawl-max` | `2` / `500` | crawler bounds |
| `-screenshot` / `-chrome` | false / auto | screenshot with system Chrome |
| `-emit` | — | machine-friendly stdout findings |
| `-webhook` | — | notification webhook |
| `-o` / `-format` | `results/` | output path & format |
| `-silent` | false | no UI, one line per target |
| `-no-color` | false | disable colors |
| `-h`, `--help` | — | full help |
| `-version` | — | print version |

---

## Contributing

PRs welcome. New signatures and passive sources are the easiest place to start.

### Setup

```bash
git clone https://github.com/Arseno25/dscan.git
cd dscan
go build ./...
go test ./...
```

Go 1.24+. The only direct dependency is [`pterm`](https://github.com/pterm/pterm) for the UI — please keep it that way.

Before opening a PR:

```bash
gofmt -l .        # must print nothing
go vet ./...
go test ./...
```

### Project layout

```
main.go                  flag parsing → engine → report
internal/config/         CLI parsing and validation
internal/scanner/        Module interface, engine, event system, rate limiter
internal/modules/        the seven scan modules
internal/detect/         signature databases (tech, WAF, CDN, takeover)
internal/data/           embedded wordlist + port specs
internal/report/         JSON/JSONL/CSV/Markdown/HTML/TXT writers
internal/ui/             terminal renderer
```

The engine runs targets in parallel and modules **sequentially per target**, because
modules feed each other: `dns` produces the IPs `ports` and `vhost` scan, `sub`
produces the hosts `http` probes and the CNAMEs `takeover` inspects. Modules
parallelize internally with their own worker pools.

### Adding a scan module

Implement `scanner.Module` and register it in `modules.All()` — position in that
slice *is* the execution order, so place it after whatever fills the fields it reads.

```go
type MyModule struct{}

func (MyModule) Name() string { return "mine" }

func (MyModule) Run(ctx context.Context, sc *scanner.ScanContext) error {
    sc.Limit(ctx)                          // respect -rate
    sc.Found("live", "found %s", host)     // drives the UI counters
    sc.Result.Web = append(sc.Result.Web, ...)
    return nil
}
```

Rules a module must follow:

- Honour `ctx` on every network call and select on `ctx.Done()` when feeding a job channel.
- Call `sc.Limit(ctx)` before each network operation.
- Size worker pools with `min(sc.Opts.Workers, len(work))`.
- Return an error only for a real failure. "Nothing found" is `nil` — a `tls` module finding no TLS is not a module error.
- Never report a finding from an ambiguous signal. A DNS timeout is not an NXDOMAIN; a failed fetch is not a takeover.

### Adding signatures

| What | Where | Format |
|------|-------|--------|
| Technology (70) | `internal/detect/signatures.go` | `sig("Name", "regex")` — matched case-insensitively against headers + body |
| WAF (18) | `internal/detect/signatures.go` | same, matched against headers only |
| CDN (8) | `internal/detect/detect.go` | substring of the `Server` header |
| Takeover (48) | `internal/detect/takeover.go` | `{"suffix.tld", "Service", "unclaimed-page marker"}` |

For a takeover fingerprint, `Suffix` is matched on a label boundary, and the third
field is the lowercase marker the service returns when the name is dangling.
Leave it `""` if the service goes NXDOMAIN instead — 29 of the 48 have a marker.
Cross-check against [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).

### Adding a passive source

Add a `fetch` func in `internal/modules/subdomain.go` and append it to
`passiveSources`. It must be keyless and free, wrap the target in `esc()`, and
return an error rather than partial garbage — one dead source must not fail the scan.

### Tests

No frameworks, stdlib `testing` only. Anything with a branch, a parser, or a
security decision needs a test; wiring code does not. Parsers get their invalid
inputs tested, not just the happy path.

### Commits

Conventional Commits (`fix:`, `feat:`, `refactor:`, `test:`, `docs:`). Explain
*why* in the body — the diff already shows what. Keep unrelated changes in
separate commits, and make sure each one builds on its own.

---

<div align="center">
developed by <b>shadow0x0</b> · for authorized security testing & bug bounty
</div>

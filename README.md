<div align="center">

<img src="assets/logo.svg" width="700" alt="NexProwl"/>

# NexProwl

**A fast, single-binary reconnaissance engine for DNS, subdomains, ports, HTTP, TLS, virtual hosts, takeovers, and crawling.**

[![CI](https://github.com/Arseno25/nexprowl/actions/workflows/ci.yml/badge.svg)](https://github.com/Arseno25/nexprowl/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Arseno25/nexprowl?sort=semver)](https://github.com/Arseno25/nexprowl/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/Arseno25/nexprowl.svg)](https://pkg.go.dev/github.com/Arseno25/nexprowl)
[![Go Report Card](https://goreportcard.com/badge/github.com/Arseno25/nexprowl)](https://goreportcard.com/report/github.com/Arseno25/nexprowl)
[![Go 1.24+](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![Coverage floor 70%](https://img.shields.io/badge/coverage-70%25%20floor-22c55e)](.github/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e)](LICENSE)

</div>

> [!WARNING]
> **Authorized testing only.** NexProwl sends real traffic to the targets you
> give it — port scans, virtual host fuzzing, zone transfer attempts, crawling.
> Use it only against systems you own, have written permission to test, or that
> are in scope for a bug bounty program you are participating in. Running it
> against anything else may be a criminal offence in your jurisdiction. You are
> responsible for how you use this tool. See [Disclaimer](#disclaimer).

---

## Contents

- [Why NexProwl](#why-nexprowl)
- [Demo](#demo)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Pipelines](#pipelines)
- [Output formats](#output-formats)
- [Configuration](#configuration)
- [Screenshots](#screenshots)
- [Responsible scanning](#responsible-scanning)
- [Run history and comparison](#run-history-and-comparison)
- [Flag reference](#flag-reference)
- [Exit codes](#exit-codes)
- [Development](#development)
- [Testing](#testing)
- [Verifying a release](#verifying-a-release)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)
- [Disclaimer](#disclaimer)

## Why NexProwl

Recon usually means gluing together subfinder, gobuster, rustscan, httpx,
wappalyzer, wafw00f, dnsrecon, and subjack with shell pipes, then reconciling
eight output formats by hand.

NexProwl runs eight modules in one process. They feed each other inside a single
run — `dns` produces the IPs that `ports` and `vhost` scan, `sub` produces the
hosts `http` probes and the CNAMEs `takeover` inspects — so nothing is
re-resolved and nothing is lost between tools. Targets run in parallel, and each
module parallelizes internally.

- **One static binary.** No Python, no Node, no package manager, no runtime.
- **One direct dependency** ([`pterm`](https://github.com/pterm/pterm), for the
  terminal UI). Everything else is the Go standard library.
- **Every scan is a diffable snapshot.** Directory-mode runs are immutable and
  timestamped, so `nexprowl diff` tells you what changed in an attack surface.
- **Built to be piped.** Targets on STDIN, findings on stdout, JSON everywhere.

## Demo

<!-- Recording instructions: docs/DEMO.md -->

*A terminal recording is not committed yet. It will live at
`docs/assets/nexprowl-demo.gif` — see [docs/DEMO.md](docs/DEMO.md) for the
recipe, including the rule that demos may only target `example.com` or a
lab host you own.*

## Features

| Module | Capabilities |
|--------|--------------|
| `dns` | A/AAAA/MX/NS/TXT/CAA/SOA/SRV/PTR · SPF/DMARC · ASN ownership · null-MX · wildcard detection · **AXFR zone transfer** |
| `sub` | 5 keyless passive sources (crt.sh, certspotter, otx, hackertarget, anubis) + 3 optional keyed sources · TLS SAN harvesting · wordlist bruteforce · wildcard filtering |
| `ports` | Multi-host/IP TCP connect scan · service naming · **banner grabbing** |
| `http` | Port-aware HTTP/HTTPS probing · body and favicon hashes · response timing · technology, WAF, and CDN detection |
| `vhost` | Hidden virtual host discovery · Host-header + **SNI fuzzing** · wildcard-noise size-model filter |
| `tls` | Multi-endpoint certificates · cipher · issuer · expiry · hostname mismatch · SANs fed back into discovery |
| `takeover` | Dangling CNAME detection · claimable-service fingerprints · NXDOMAIN **plus unclaimed-page body verification**, which catches GitHub Pages, Shopify, and Heroku — services whose dangling names keep resolving |
| `crawl` | Bounded same-scope HTML/JS/robots/sitemap endpoint discovery |

Plus: run history and `nexprowl diff` · zoomable HTML architecture map ·
STDIN/`-emit` pipelines · screenshots via system Chrome · webhook notifications ·
custom resolvers · DNS-over-HTTPS · proxy support · rate limiting and jitter ·
JSON/JSONL/CSV/Markdown/HTML/TXT output.

## Architecture

```
main.go                  subcommand dispatch → config → engine → report
internal/config/         CLI parsing, validation, and clamping
internal/scanner/        Module interface, engine, event system, rate limiter,
                         DoH resolver, proxy wiring, build metadata
internal/modules/        the eight scan modules + screenshot capture
internal/detect/         signature databases (tech, WAF, CDN, takeover)
internal/data/           embedded wordlist + port specs
internal/report/         JSON/JSONL/CSV/Markdown/HTML/TXT writers, diff,
                         run manifest, architecture map, webhooks
internal/ui/             terminal renderer, banner, help screen
```

The engine runs **targets in parallel** and **modules sequentially per target**,
because modules depend on each other's output. Module order in `modules.All()`
*is* execution order. Each module owns its worker pool, bounded by `-t`.

Events flow from the engine to the UI through a single `Emitter` channel, so the
scan logic never touches the terminal and `-silent` costs nothing.

## Installation

NexProwl is a single Go binary. The two shortest routes both **compile it on
your own machine** — no release download, nothing to trust but the source.

| You have | Command |
|---|---|
| Go 1.24+ | `go install github.com/Arseno25/nexprowl@latest` |
| Go 1.24+ and git | `git clone ... && make install` — [below](#clone-and-build) |
| Neither | [download a release binary](#download-a-release) |
| Docker | [build the image](#docker) |

`go install` *is* clone-and-build: it fetches the source, compiles it locally,
and drops the binary on your `PATH` in one command. Clone manually only when you
want to read the code, modify it, or run the tests.

### Go install

Requires Go 1.24 or newer.

```bash
go install github.com/Arseno25/nexprowl@latest
```

The binary lands in `$(go env GOPATH)/bin`. Add it to your `PATH` if it is not
there already.

> A binary installed this way reports `dev` for its version — the release
> metadata is injected by the linker during a release build, and `go install`
> does not apply those flags.

### Clone and build

```bash
git clone https://github.com/Arseno25/nexprowl.git
cd nexprowl
make install     # or: make build, to leave ./nexprowl in the working directory
nexprowl --help
```

`make install` puts the binary in `$(go env GOPATH)/bin`, stamping the version,
commit, and build date so `nexprowl version` reports something meaningful rather
than `dev`.

No make? The plain Go commands work fine:

```bash
go build -trimpath -ldflags="-s -w" -o nexprowl .    # ./nexprowl
go install .                                          # onto your PATH
```

Windows PowerShell:

```powershell
go build -trimpath -ldflags="-s -w" -o nexprowl.exe .
.
exprowl.exe --help
```

The CLI entrypoint is the module root package, so the build path is `.` rather
than `./cmd/nexprowl`.

Other useful targets — run `make help` for the full list:

| Target | What it does |
|---|---|
| `make build` | Build `./nexprowl` with version metadata |
| `make install` | Build and install onto your `PATH` |
| `make test` | Run the test suite |
| `make race` | Run tests under the race detector |
| `make cover` | Run tests and enforce the 70% coverage floor |
| `make check` | Everything CI checks |
| `make clean` | Remove build and test artifacts |

Platform-by-platform notes live in [docs/USAGE.md](docs/USAGE.md).


### Download a release

Prebuilt static binaries for Linux, macOS, and Windows on amd64 and arm64 are
attached to every [release](https://github.com/Arseno25/nexprowl/releases/latest).

1. Open the [latest release](https://github.com/Arseno25/nexprowl/releases/latest).
2. Download the archive matching your platform:
   `nexprowl_<version>_<os>_<arch>.tar.gz` — or `.zip` on Windows.
3. Download `checksums.txt` and [verify it](#verifying-a-release).
4. Extract and install.

Linux / macOS:

```bash
tar -xzf nexprowl_0.1.0_linux_amd64.tar.gz
sudo install -m 0755 nexprowl /usr/local/bin/
nexprowl version
```

Windows PowerShell:

```powershell
Expand-Archive .\nexprowl_0.1.0_windows_amd64.zip -DestinationPath .\nexprowl
.\nexprowl\nexprowl.exe version
```

`.deb` and `.rpm` packages for linux/amd64 and linux/arm64 are attached to the
same release:

```bash
sudo dpkg -i nexprowl_0.1.0_linux_amd64.deb     # Debian / Ubuntu
sudo rpm -i  nexprowl_0.1.0_linux_amd64.rpm     # Fedora / RHEL / openSUSE
```

There is no hosted APT or DNF repository, so these do not auto-update — reinstall
to upgrade.

#### If your OS blocks the download

Both cases below apply to **downloaded** binaries only. Building from source
avoids them entirely, which is one more reason `go install` is the recommended
route.

**macOS.** Gatekeeper blocks the binary on first run because the release is not
notarized. The quarantine flag is set by the *downloading application*, so a
`curl` download is unaffected while a browser download is not. Clear it with:

```bash
xattr -d com.apple.quarantine /usr/local/bin/nexprowl
```

**Windows.** The archive carries a Mark of the Web, which SmartScreen may act
on. Clear it with:

```powershell
Unblock-File .\nexprowl.exe
```

Microsoft Defender and other antivirus products also flag recon tooling as
`HackTool`/`PUA` on behaviour rather than signature — this is common to the whole
category and is not something a code-signing certificate fixes. If that happens,
build from source or add an exclusion for a path you control.

### Docker

```bash
docker build -t nexprowl:local .
docker run --rm nexprowl:local version
docker run --rm -v "$PWD/results:/results" nexprowl:local example.com
```

The image is a multi-stage build on `distroless/static` — no shell, no package
manager, running as a non-root user. **`-screenshot` does not work in it**: that
flag drives an installed Chrome, and bundling a browser would multiply the image
size and reintroduce a large attack surface. See the notes at the bottom of the
[`Dockerfile`](Dockerfile).

No image is published to a registry yet.

### Not available yet

There is **no** Homebrew formula or tap, Scoop bucket, AUR package, APT or
DNF repository, distribution-official package (Debian, Ubuntu, Fedora, Kali,
Arch), or published container image. `brew install nexprowl` and
`apt install nexprowl` do **not** work.

Building from source is the supported path, and it is deliberately the simplest
one: `go install` compiles on your machine in a single command. See the
[Roadmap](#roadmap) for what may come later.

Anyone distributing a "NexProwl" package through a channel not listed above is
not doing so with the maintainer's involvement.

## Quick start

```bash
# Everything, one target
nexprowl example.com

# Pick your modules
nexprowl example.com -m dns,sub,http,tls

# Machine-readable output
nexprowl example.com -o result.json -format json

# Read targets from a pipeline, print discovered URLs
echo example.com | nexprowl -silent -emit urls

# Full flag reference
nexprowl --help
```

## Usage

### Targets

A target is a hostname, an IP, or a URL — URLs and ports are stripped down to
the host, and a leading `*.` is removed:

```bash
nexprowl example.com
nexprowl https://sub.example.com/path      # → sub.example.com
nexprowl 192.0.2.10
```

Multiple targets, a file, or STDIN:

```bash
nexprowl example.com api.example.com
nexprowl -l targets.txt -T 10              # 10 concurrent targets
cat domains.txt | nexprowl -silent
```

STDIN is read automatically when no target is given on the command line and
stdin is not a terminal. There is no `-stdin` flag.

`targets.txt` format — one per line, `#` starts a comment, duplicates dropped:

```
# production
example.com
api.example.com
https://sub.example.com/path
```

### Module selection

```bash
nexprowl example.com                          # all eight modules (default)
nexprowl example.com -m dns,sub,http,tls
nexprowl example.com -m dns                   # DNS records + AXFR attempt only
nexprowl example.com -m dns,vhost             # hunt hidden virtual hosts
```

Valid names: `dns`, `sub`, `ports`, `http`, `vhost`, `tls`, `takeover`, `crawl`.
An unknown name is a fatal error rather than a silent skip.

### Scan tuning

```bash
nexprowl example.com -m sub,http -t 500       # 500 workers per module
nexprowl example.com -p 1-10000 -t 1000       # wide port scan
nexprowl example.com -p top100                # default
nexprowl example.com -p full                  # all 65535 ports
nexprowl example.com -p 80,443,8080,8443
nexprowl example.com -w wordlist.txt          # custom subdomain wordlist
nexprowl example.com -passive                 # passive sources only, no bruteforce
nexprowl example.com -timeout 10              # slow links
```

### Scope

Discovered hosts and HTTP redirects are both checked against scope, so a
redirect off-target does not drag the scan with it.

```bash
nexprowl example.com -include example.net,example.org
nexprowl example.com -exclude admin.example.com,internal.example.com
nexprowl example.com -max-hosts 2000
```

### Resolvers and DNS

```bash
nexprowl example.com -r resolvers.txt         # round-robin custom resolvers
nexprowl example.com -doh                     # DNS-over-HTTPS via Cloudflare
```

`resolvers.txt` — a bare address gets `:53` appended:

```
8.8.8.8
1.1.1.1
9.9.9.9
1.0.0.1:53
```

### Proxy

```bash
nexprowl example.com -proxy socks5://127.0.0.1:9050
nexprowl example.com -proxy socks5h://127.0.0.1:9050   # resolve DNS at the proxy
nexprowl example.com -proxy http://proxy.internal:8080
```

Supported schemes: `http`, `https`, `socks5`, `socks5h`. An unparseable proxy URL
is rejected at startup rather than silently ignored.

The proxy covers HTTP traffic. To keep DNS off the local network as well, combine
it with `-doh` or `socks5h://`.

### User agent

Scan requests are sent with a fixed user agent, `Mozilla/5.0 NexProwl/<version>`.
It is not configurable from the command line; a `-user-agent` flag is on the
[roadmap](#roadmap).

### Webhooks

```bash
nexprowl example.com -o results/ -webhook https://hooks.example.com/scan
nexprowl diff -webhook https://hooks.example.com/diff results/OLD results/NEW
```

Posts a JSON scan summary (or the full diff) to the URL. Only `http` and `https`
URLs are accepted, the client verifies TLS certificates normally, and redirects
are **not** followed — the payload contains your scan results, and a redirect
would replay it to a host you never named. A webhook failure warns on stderr and
does not fail the scan.

## Pipelines

`-emit` writes one finding per line to stdout and implies `-silent`, so NexProwl
drops straight into a shell pipeline:

```bash
# Feed live URLs to nuclei
nexprowl example.com -emit urls | nuclei -silent

# Subdomains into your own tooling
nexprowl example.com -m sub -passive -emit subdomains > subs.txt

# host:port pairs
nexprowl example.com -m dns,ports -emit hostports

# Full results as JSONL, one object per target
nexprowl -l targets.txt -emit jsonl | jq -r '.target'

# Chain: read targets from a file, emit endpoints
cat domains.txt | nexprowl -emit endpoints
```

Emit modes: `subdomains`, `urls`, `hostports`, `ips`, `endpoints`, `jsonl`.

`-silent` on its own prints one summary line per target instead of the live UI:

```
example.com subs=42 ports=3 live=8 takeovers=0 (12043ms)
```

## Output formats

The format comes from the `-o` file extension, or `-format` overrides it.

| `-o` value | Result |
|---|---|
| `results/out.json` | Combined pretty JSON |
| `results/out.jsonl` | One result object per line — pipe-ready for `jq` and `nuclei` |
| `results/out.csv` | Flattened CSV: target, host, IPs, URL, status, tech, WAF, ports |
| `results/out.md` | Markdown report with per-target tables |
| `results/out.html` | Standalone HTML report with a zoomable, fullscreen architecture map |
| `results/out.txt` | Plain-text summary |
| `results/` *(no extension)* | **Directory mode** — see below |

Format override: `-format json|jsonl|csv|md|html|txt`.

**Directory mode** (the default, `-o results`) writes an immutable timestamped
run folder containing:

```
results/20260115-143022-517/
├── example.com.json        per-target results
├── summary.csv             flattened summary of every target
├── report.html             HTML report + architecture map
├── architecture.md         architecture map as Markdown
├── manifest.json           run metadata and finding counts
├── subdomains.txt          plain asset lists, one per line
├── urls.txt
├── hostports.txt
├── endpoints.txt
├── ips.txt
└── screenshots/            only with -screenshot
results/latest.txt          name of the most recent run
```

Writing to a single file also produces an `architecture.md` companion next to it.

## Configuration

NexProwl has no config file — everything is a flag. The only environment
variables are optional API keys that unlock three extra passive subdomain
sources in the `sub` module:

```bash
export NEXPROWL_SECURITYTRAILS_KEY=...
export NEXPROWL_VIRUSTOTAL_KEY=...
export NEXPROWL_SHODAN_KEY=...
```

Without them, the five keyless sources still run. A source that fails is
reported in the `sources` section of the results and never fails the scan.

Keys are read from the environment on every run. Anything that can read your
environment can read them; treat them accordingly, and prefer a secrets manager
over shell history.

## Screenshots

```bash
nexprowl example.com -screenshot
nexprowl example.com -screenshot -chrome /usr/bin/chromium
```

**Requirements:**

- An installed **Chrome, Chromium, or Edge**. NexProwl shells out to it in
  headless mode rather than bundling a browser — that is what keeps the binary
  small and dependency-free.
- Auto-detected from `PATH` (`chrome`, `google-chrome`, `chromium`,
  `chromium-browser`, `msedge`) and from the standard install locations on
  Windows. Point at a specific binary with `-chrome PATH`.
- Screenshots are captured **one at a time**, after the scan completes, into
  `<output>/screenshots/`, named by a hash of the URL.
- Each capture gets a disposable Chrome profile in the temp directory, removed
  afterwards, and is killed after 25 seconds.
- Certificate errors are ignored during capture, since the point is to see what
  the host serves.
- **Does not work in the Docker image** — no browser is installed there.

A missing browser warns on stderr and does not fail the scan.

## Responsible scanning

Default settings are tuned for a cooperative target on a good network: 300
workers per module, 5 concurrent targets, a 4-second timeout, and no rate limit.
That is a lot of traffic. **Turn it down before pointing NexProwl at anything
you do not run yourself.**

```bash
# One flag: 10 workers, 10 ops/sec, 8s timeout, passive-only
nexprowl -stealth example.com

# Manual throttle
nexprowl example.com -rate 50 -t 50

# Add random 0-500ms delay between requests
nexprowl example.com -jitter 500

# Tor + DoH + jitter
nexprowl -stealth -doh -jitter 500 -proxy socks5://127.0.0.1:9050 example.com
```

Guidelines:

- **`-rate N`** caps network operations per second **per target**. With `-T 10`,
  ten targets at `-rate 50` is up to 500 ops/sec in total. Budget accordingly.
- **`-active`** enables intrusive checks such as active WAF probing. It is off by
  default and should stay off unless your engagement scope covers it.
- **AXFR attempts** run as part of the `dns` module. Zone transfer requests are
  logged by the target's nameservers.
- **`-p full`** scans 65535 ports per host. On a target with hundreds of
  discovered subdomains and `-ports-subs`, that is millions of connections.
  Check `-max-hosts` first.
- Bug bounty programs frequently specify rate limits in their rules. `-rate` is
  how you comply with them.

Resource ceilings are enforced so a typo cannot exhaust your own machine: `-t` is
capped at 10000, `-T` at 1000, `-timeout` at 3600 seconds, and `-max-hosts` at
1000000. Values below the minimum are raised to 1.

## Run history and comparison

Every directory-mode scan writes a new immutable run folder, so history
accumulates on its own:

```bash
nexprowl example.com -o results/        # results/20260115-143022-517/
nexprowl example.com -o results/        # results/20260118-091544-203/
cat results/latest.txt                  # 20260118-091544-203
```

Compare two runs:

```bash
nexprowl diff results/20260115-143022-517 results/20260118-091544-203
nexprowl diff -o results/diff.json results/OLD results/NEW
nexprowl diff -webhook https://hooks.example.com/changes results/OLD results/NEW
```

The diff reports additions and removals across subdomains, URLs, host:port
pairs, IPs, endpoints, **web state** (status, title, body hash, technologies),
**TLS state** (version, expiry, hostname mismatch), and takeover candidates.

It exits **`3`** when anything changed, which makes attack-surface monitoring a
two-line cron job:

```bash
nexprowl example.com -o /var/lib/recon/ -silent
nexprowl diff -webhook "$SLACK_URL" \
  /var/lib/recon/$(cat /var/lib/recon/previous.txt) \
  /var/lib/recon/$(cat /var/lib/recon/latest.txt) || echo "attack surface changed"
```

`diff` also accepts single JSON result files, not just run directories.

## Flag reference

`nexprowl --help` is authoritative — this table mirrors it.

### Commands

| Command | Description |
|---|---|
| `nexprowl [flags] TARGET...` | Scan one or more targets |
| `nexprowl diff [-o FILE] [-webhook URL] OLD NEW` | Compare two saved runs; exit `3` if changed |
| `nexprowl version` | Print version, commit, build date, Go version, OS/arch |

### Targets

| Flag | Default | Description |
|------|---------|-------------|
| `-l FILE` | — | Target list file, one per line, `#` for comments |

### Modules

| Flag | Default | Description |
|------|---------|-------------|
| `-m LIST` | all eight | `dns,sub,ports,http,vhost,tls,takeover,crawl` |

### Scan tuning

| Flag | Default | Description |
|------|---------|-------------|
| `-p SPEC` | `top100` | Ports: `top100` · `full` · `80,443` · `1-1024` |
| `-w FILE` | built-in | Custom subdomain wordlist |
| `-passive` | `false` | Passive sources only, skip bruteforce |
| `-probe-subs` | `true` | HTTP-probe discovered subdomains |
| `-scan-all-ips` | `false` | Port-scan every resolved IPv4/IPv6 address |
| `-ports-subs` | `false` | Port-scan discovered subdomains |
| `-probe-both` | `false` | Probe both HTTP and HTTPS on web ports |
| `-active` | `false` | Enable intrusive checks such as active WAF probing |
| `-crawl-depth N` | `2` | Maximum crawler depth |
| `-crawl-max N` | `500` | Maximum crawled URLs per target |

### Performance and stealth

| Flag | Default | Description |
|------|---------|-------------|
| `-t N` | `300` | Workers per module (max 10000) |
| `-T N` | `5` | Concurrent targets in batch mode (max 1000) |
| `-timeout N` | `4` | Network timeout in seconds (max 3600) |
| `-rate N` | `0` (unlimited) | Max network ops/sec **per target** |
| `-jitter MS` | `0` | Random 0..MS delay between requests |
| `-stealth` | `false` | Preset: workers 10, rate 10, timeout 8, passive-only |
| `-r FILE` | system DNS | Custom DNS resolvers, round-robin |
| `-doh` | `false` | DNS-over-HTTPS via Cloudflare |
| `-proxy URL` | — | `http://` · `https://` · `socks5://` · `socks5h://` |

### Scope

| Flag | Default | Description |
|------|---------|-------------|
| `-include LIST` | — | Extra in-scope domains, comma-separated |
| `-exclude LIST` | — | Out-of-scope domains, comma-separated |
| `-max-hosts N` | `10000` | Maximum discovered hosts per target (max 1000000) |

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-o PATH` | `results` | Output file or directory |
| `-format FMT` | from extension | `json` · `jsonl` · `csv` · `md` · `html` · `txt` |
| `-emit FIELD` | — | stdout findings: `subdomains` · `urls` · `hostports` · `ips` · `endpoints` · `jsonl` (implies `-silent`) |
| `-screenshot` | `false` | Capture live pages with installed Chrome/Chromium |
| `-chrome PATH` | auto-detect | Chrome/Chromium executable |
| `-webhook URL` | — | POST scan summary to a webhook |
| `-silent` | `false` | No UI — one summary line per target |
| `-no-color` | `false` | Disable colored output |

### Misc

| Flag | Description |
|------|-------------|
| `-h`, `-help`, `--help` | Full help screen |
| `-version`, `--version` | Same output as `nexprowl version` |

Flags may appear before or after the target: `nexprowl -t 200 example.com` and
`nexprowl example.com -t 200` are equivalent.

There is no verbose or debug flag. The live UI shows per-module progress; use
`-emit jsonl` or the JSON output for full detail.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. For `diff`, no changes found |
| `1` | Fatal error — invalid flags, unreadable target list, unwritable output path, failed diff |
| `3` | `nexprowl diff` only: the two runs differ |

A scan that finishes with per-module errors still exits `0`; the errors are
recorded in the `errors` field of the results. Exit codes reflect whether
NexProwl worked, not what it found — an unreachable target is a finding, not a
failure.

## Development

```bash
git clone https://github.com/Arseno25/nexprowl.git
cd nexprowl
go build ./...
go test ./...
```

Go 1.24+. The only direct dependency is
[`pterm`](https://github.com/pterm/pterm) — please keep it that way.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide: adding a module,
adding detection signatures, adding a passive source, and the rules every module
must follow around context cancellation, rate limiting, and scope.

## Testing

```bash
gofmt -l .                                  # must print nothing
go vet ./...
go test -count=1 ./...
go test -count=1 -race ./...                # needs a C compiler installed
go test -coverprofile=coverage.out ./...    # project floor: 70%
go tool cover -func=coverage.out | tail -1
```

Standard library `testing` only — no assertion libraries, no mocking frameworks.
Tests must never depend on live internet services; use `httptest.Server`,
`t.TempDir()`, and the mock resolver pattern in
`internal/scanner/context_test.go`.

CI runs format, vet, race tests, the coverage floor, a cross-compile of all six
release targets, and `goreleaser check` on every pull request.

## Verifying a release

Every release publishes `checksums.txt` with SHA-256 hashes of all archives.

Linux / macOS:

```bash
sha256sum -c checksums.txt --ignore-missing
```

Windows PowerShell:

```powershell
(Get-FileHash .\nexprowl_0.1.0_windows_amd64.zip -Algorithm SHA256).Hash.ToLower()
Select-String -Path .\checksums.txt -Pattern 'windows_amd64'
```

The two values must match. If they do not, do not run the binary.

Confirm you are running a real release build rather than a local compile:

```bash
nexprowl version
```

```
NexProwl 0.1.0
  commit:  9f2c1a4e8b7d3f5a1c6e0b2d4f8a7c3e5b9d1f6a
  built:   2026-01-15T14:30:22Z
  go:      go1.24.0
  os/arch: linux/amd64
```

`dev` / `none` / `unknown` means the binary was built locally without linker
flags, which is expected for `go install` and `go build`.

## Roadmap

Nothing here is implemented. Contributions welcome — open an
[issue](https://github.com/Arseno25/nexprowl/issues/new/choose) before starting
something large.

**Distribution**

- [x] `.deb` / `.rpm` packages attached to each release
- [ ] Homebrew tap — needs a second repository and a token that can write to it
- [ ] Hosted APT / DNF repositories — need a GPG signing key kept in CI, which
      is a credential that can vouch for packages installed as root, so it is
      not something to set up casually
- [ ] Scoop bucket (template in [`packaging/scoop/`](packaging/scoop/nexprowl.json))
- [ ] Published container image on GHCR
- [ ] AUR package
- [ ] Submission to distribution-official repositories (Debian, Kali) — needs a
      distro maintainer sponsor, so this is a long game rather than a task

**CLI**

- [ ] Shell completions (bash, zsh, fish) — needs a CLI framework the stdlib
      `flag` package cannot provide
- [ ] Man page
- [ ] Configurable `-user-agent`
- [ ] Config file support for repeated engagements

**Scanning**

- [ ] More passive sources and takeover fingerprints
- [ ] Resumable scans
- [ ] IPv6-first scanning mode

**Project**

- [ ] Recorded terminal demo ([docs/DEMO.md](docs/DEMO.md))
- [ ] Signed release artifacts (cosign / SLSA provenance)

## Contributing

Pull requests are welcome. New detection signatures and passive sources are the
easiest place to start.

Read [CONTRIBUTING.md](CONTRIBUTING.md) first — it covers the fork-and-branch
workflow, formatting, testing rules, commit conventions, and the extra scrutiny
that applies to security-sensitive changes.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

For questions rather than defects, see [SUPPORT.md](SUPPORT.md).

## Security

**Do not open a public issue for a security vulnerability.** Report privately at
<https://github.com/Arseno25/nexprowl/security/advisories/new>.

[SECURITY.md](SECURITY.md) covers supported versions, what a good report
contains, the response process, coordinated disclosure expectations, and what is
explicitly out of scope — including why certificate verification is
intentionally disabled for scan traffic but not for webhooks or DoH.

## License

[MIT](LICENSE).

## Disclaimer

NexProwl is built for **authorized** security testing: engagements you have
written permission for, bug bounty programs whose scope covers the target, and
assets you own.

Most modules send traffic to the target. Port scanning, virtual host fuzzing,
zone transfer attempts, crawling, and `-active` probes are observable and
attributable to you. Running them against infrastructure you are not authorized
to test may violate computer misuse laws in your jurisdiction, regardless of
intent and regardless of whether anything was damaged.

Scan output routinely contains sensitive information about the systems you
tested. It is written with ordinary file permissions to wherever you point `-o`.
Store, transmit, and dispose of it accordingly.

The authors and contributors accept no liability for how this tool is used.
**You are responsible for how you use it.**

---

<div align="center">
developed by <b>shadow0x0</b> · for authorized security testing and bug bounty
</div>

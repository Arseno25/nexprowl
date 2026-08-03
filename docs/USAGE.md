# NexProwl — Build and Usage Guide

> by shadow0x0 · run `nexprowl version` to see which build you have

Platform-by-platform build notes. For prebuilt binaries, `go install`, Docker,
and the full flag reference, see the [README](../README.md).

**Authorized testing only.** Every example below assumes the target is one you
own or have written permission to test.

## Install without building

```bash
go install github.com/Arseno25/nexprowl@latest
```

Or download an archive for your platform from the
[releases page](https://github.com/Arseno25/nexprowl/releases/latest) and verify
it against `checksums.txt` — see
[Verifying a release](../README.md#verifying-a-release).

## Build from source

Go 1.24 or newer is required.

```bash
git clone https://github.com/Arseno25/nexprowl.git
cd nexprowl
```

The CLI entrypoint is the module root package, so every build path below is `.`.

## Windows

### PowerShell

```powershell
go build -trimpath -ldflags="-s -w" -o nexprowl.exe .
.\nexprowl.exe --help
.\nexprowl.exe example.com
.\nexprowl.exe -l targets.txt -T 10
```

Optional: copy `nexprowl.exe` into a directory listed in your `PATH`.

```powershell
.\nexprowl.exe example.com -o results\out.html
.\nexprowl.exe example.com -screenshot
.\nexprowl.exe diff -o results\diff.json results\OLD results\NEW
```

## Linux

```bash
go build -trimpath -ldflags="-s -w" -o nexprowl .
chmod +x nexprowl
./nexprowl --help

# Optional system-wide install
sudo mv nexprowl /usr/local/bin/
nexprowl example.com
```

```bash
# Background batch scan
nohup nexprowl -l targets.txt -T 10 -o results/ > scan.log 2>&1 &

# Pipeline mode
cat targets.txt | nexprowl -silent -emit urls
```

## macOS

```bash
go build -trimpath -ldflags="-s -w" -o nexprowl .
chmod +x nexprowl
./nexprowl --help

# Optional system-wide install
sudo mv nexprowl /usr/local/bin/
nexprowl example.com
```

## Stamping version metadata into a local build

A plain `go build` reports `dev` / `none` / `unknown` from `nexprowl version`.
To stamp real values, pass them to the linker:

```bash
go build -trimpath -ldflags="-s -w \
  -X github.com/Arseno25/nexprowl/internal/scanner.Version=$(git describe --tags --always) \
  -X github.com/Arseno25/nexprowl/internal/scanner.Commit=$(git rev-parse HEAD) \
  -X github.com/Arseno25/nexprowl/internal/scanner.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o nexprowl .
```

Release builds do this automatically through GoReleaser.

## Usage Scenarios

```bash
# Full help
nexprowl --help

# Build metadata
nexprowl version

# Passive bug bounty recon
nexprowl -l scope.txt -m dns,sub -passive -silent -o results/subs.jsonl

# Full recon with an HTML report
nexprowl target.com -o results/report.html

# Rate-limited scan with custom resolvers
nexprowl target.com -r resolvers.txt -rate 30 -timeout 6

# Subdomain takeover hunting
nexprowl -l targets.txt -m sub,takeover -T 10 -o results/takeover.md

# Zone transfer check
nexprowl target.com -m dns -silent

# Wide port scan
nexprowl target.com -p 1-10000 -t 1000 -m ports

# Hidden virtual-host discovery
nexprowl target.com -m dns,vhost

# Large batch with timestamped output
nexprowl -l 1000_targets.txt -T 20 -t 200 -o results/
```

## Optional Provider Keys

```bash
export NEXPROWL_SECURITYTRAILS_KEY=...
export NEXPROWL_VIRUSTOTAL_KEY=...
export NEXPROWL_SHODAN_KEY=...
```

PowerShell:

```powershell
$env:NEXPROWL_SECURITYTRAILS_KEY = "..."
$env:NEXPROWL_VIRUSTOTAL_KEY = "..."
$env:NEXPROWL_SHODAN_KEY = "..."
```

## Input Files

`targets.txt` accepts one target per line:

```text
# comments with #
example.com
target.co.id
https://sub.domain.com/path
```

`resolvers.txt` accepts one DNS resolver per line:

```text
8.8.8.8
1.1.1.1
9.9.9.9
1.0.0.1:53
```

A custom subdomain wordlist passed through `-w` contains one label per line:

```text
admin
panel
staging
internal-api
```

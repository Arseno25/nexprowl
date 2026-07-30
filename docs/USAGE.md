# NexProwl — Build and Usage Guide

> NexProwl v2.1.0 · by shadow0x0

NexProwl does not publish release binaries. Build it locally after cloning the
repository. Go 1.24 or newer is required.

## Clone

```bash
git clone https://github.com/Arseno25/dscan.git NexProwl
cd NexProwl
```

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

## Usage Scenarios

```bash
# Full help
nexprowl --help

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

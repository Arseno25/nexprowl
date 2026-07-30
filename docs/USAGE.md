# dscan — Per-OS Usage Guide

> dscan v1.0.0 · by shadow0x0

---

## Windows

### PowerShell

```powershell
# Run from the project folder
.\bin\dscan-windows-amd64.exe example.com

# Rename for convenience
copy bin\dscan-windows-amd64.exe dscan.exe
.\dscan.exe example.com

# Batch + structured output
.\dscan.exe -l targets.txt -T 10 -o results\

# All output formats
.\dscan.exe example.com -o out.json
.\dscan.exe example.com -o out.md
.\dscan.exe example.com -o out.csv
.\dscan.exe example.com -o out.jsonl
.\dscan.exe example.com -o out.txt
```

### CMD

```cmd
bin\dscan-windows-amd64.exe example.com
bin\dscan-windows-amd64.exe -l targets.txt -T 10 -o results\
```

---

## Linux

```bash
# Setup
chmod +x bin/dscan-linux-amd64
./bin/dscan-linux-amd64 example.com

# Install system-wide
sudo cp bin/dscan-linux-amd64 /usr/local/bin/dscan
dscan example.com

# Background batch scan + log
nohup dscan -l targets.txt -T 10 -o results/ > scan.log 2>&1 &

# Pipe JSONL into jq
dscan -l targets.txt -passive -silent -o subs.jsonl
cat subs.jsonl | jq -r '.subdomains[].host' | sort -u
```

---

## macOS

```bash
# Apple Silicon (M1/M2/M3)
chmod +x bin/dscan-darwin-arm64
./bin/dscan-darwin-arm64 example.com

# Intel
chmod +x bin/dscan-darwin-amd64
./bin/dscan-darwin-amd64 example.com

# Bypass Gatekeeper (unsigned binary)
xattr -d com.apple.quarantine bin/dscan-darwin-arm64

# Install system-wide
sudo cp bin/dscan-darwin-arm64 /usr/local/bin/dscan
dscan example.com
```

---

## Usage Scenarios

```bash
# Full help
dscan --help

# 1. Passive bug bounty recon (no direct target contact)
dscan -l scope.txt -m dns,sub -passive -silent -o subs.jsonl

# 2. Full recon on a single target + report
dscan target.com -o report.md

# 3. Stealth scan (avoid WAF/IDS)
dscan target.com -r resolvers.txt -rate 30 -timeout 6

# 4. Subdomain takeover hunting
dscan -l targets.txt -m sub,takeover -T 10 -o takeover.md

# 5. Zone transfer check
dscan target.com -m dns -silent

# 6. Wide port scan
dscan target.com -p 1-10000 -t 1000 -m ports

# 7. Hidden vhost hunting
dscan target.com -m dns,vhost

# 8. Large batch with per-target output
dscan -l 1000_targets.txt -T 20 -t 200 -o results/
```

---

## Input File Formats

### targets.txt

```
# comments with #
example.com
target.co.id
https://sub.domain.com/path   ← normalized to sub.domain.com
```

### resolvers.txt

```
8.8.8.8
1.1.1.1
9.9.9.9
208.67.222.222
1.0.0.1:53
```

### Custom wordlist (-w)

One word per line, without the domain:

```
admin
panel
staging
internal-api
```

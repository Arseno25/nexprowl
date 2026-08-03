# Changelog

All notable changes to NexProwl are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-03

First public release. NexProwl was developed privately before this point; the
sections below describe the tool as it ships in `v0.1.0`, not a diff against an
earlier published version.

### Added

- **Eight recon modules** selectable with `-m`:
  - `dns` — A/AAAA/MX/NS/TXT/CAA/SOA/SRV/PTR records, SPF/DMARC, ASN ownership,
    wildcard detection, and AXFR zone-transfer attempts
  - `sub` — passive subdomain enumeration from keyless sources, optional keyed
    sources, TLS SAN harvesting, wordlist bruteforce, wildcard filtering
  - `ports` — multi-host/IP TCP connect scan with service naming and banner
    grabbing
  - `http` — port-aware HTTP/HTTPS probing, body and favicon hashes, response
    timing, technology/WAF/CDN detection
  - `vhost` — virtual host discovery via Host-header and SNI fuzzing with a
    wildcard-noise size model
  - `tls` — multi-endpoint certificate inspection: issuer, cipher, validity,
    expiry, hostname mismatch, SANs
  - `takeover` — dangling-CNAME detection with claimable-service fingerprints,
    verified by NXDOMAIN *and* unclaimed-page body markers
  - `crawl` — bounded same-scope HTML/JS/robots/sitemap endpoint discovery
- **Output formats**: JSON, JSONL, CSV, Markdown, HTML, and plain text, chosen
  by `-o` file extension or forced with `-format`.
- **Run history**: directory-mode scans write an immutable timestamped run under
  the output directory, plus `latest.txt` pointing at the newest run.
- **`nexprowl diff OLD NEW`** compares two saved runs across subdomains, URLs,
  host:port pairs, IPs, endpoints, web state, TLS state, and takeover
  candidates. Exit code `3` signals that something changed.
- **HTML report** with a zoomable, fullscreen architecture map.
- **Pipeline support**: STDIN target input and `-emit
  subdomains|urls|hostports|ips|endpoints|jsonl` for machine-readable stdout.
- **Scope control** with `-include` / `-exclude`, enforced on discovered hosts
  and on HTTP redirects.
- **Responsible-scanning controls**: `-rate`, `-jitter`, `-timeout`,
  `-max-hosts`, and a `-stealth` preset (workers 10, rate 10, timeout 8s,
  passive-only).
- **Traffic controls**: `-proxy` (http/https/socks5/socks5h), `-doh` for
  DNS-over-HTTPS, and `-r` for custom round-robin resolvers.
- **Screenshots** of live pages through an installed Chrome/Chromium
  (`-screenshot`, `-chrome`).
- **Webhook notifications** for scan summaries and diffs (`-webhook`).
- **Build metadata**: `nexprowl version` (and `-version` / `--version`) prints
  version, git commit, build date, Go version, and OS/architecture. Values are
  injected at link time; a plain `go build` reports `dev`.
- Prebuilt release binaries for Linux, macOS, and Windows on amd64 and arm64,
  with SHA-256 `checksums.txt`.
- `go install github.com/Arseno25/nexprowl@latest` support.
- Community documentation: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `SUPPORT.md`, issue and pull request templates.
- Multi-stage `Dockerfile` producing a non-root, distroless-style image.

### Changed

- **Module path** is now `github.com/Arseno25/nexprowl` (previously the local
  module name `nexprowl`), which is what makes `go install ...@latest` work.
  Import paths inside the repository changed accordingly. No CLI behaviour
  changed.
- **Version output is now multi-line.** `nexprowl -version` previously printed
  a single line; it now prints version, commit, build date, Go version, and
  OS/arch. Scripts parsing the old single-line format need updating.
- **Version numbering restarts at `0.1.0`.** Pre-release builds identified
  themselves as `2.1.0`, an internal development number that was never
  published. `v0.1.0` is the first public release.
- **`-webhook` no longer follows redirects.** The payload contains full scan
  results; a 307/308 redirect would have replayed it to a host the user never
  named. A redirect response is now reported as an error. Only `http` and
  `https` webhook URLs are accepted.

### Fixed

- `-t`, `-T`, `-timeout`, and `-max-hosts` are now clamped to sane ceilings
  (10000 workers, 1000 concurrent targets, 3600s, 1000000 hosts). A mistyped
  `-t 3000000` previously allocated a job channel and goroutine set large enough
  to exhaust the host.
- The `takeover` module now aborts queued candidates on context cancellation
  instead of running a DNS lookup for every remaining candidate after Ctrl-C.
- `-screenshot` no longer parks one goroutine per live host waiting on a
  single-slot semaphore; the slot is taken before the goroutine is spawned.

### Security

- Webhook delivery uses a dedicated HTTP client with explicit TLS handshake and
  response-header timeouts, full certificate verification, and no redirect
  following.
- Scan-probe clients continue to accept invalid certificates on purpose — that
  is what the `tls` module reports on. This is documented as out of scope in
  `SECURITY.md`.

[Unreleased]: https://github.com/Arseno25/nexprowl/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Arseno25/nexprowl/releases/tag/v0.1.0

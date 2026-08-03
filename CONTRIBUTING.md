# Contributing to NexProwl

Thanks for wanting to help. NexProwl is a single-binary recon engine that stays
deliberately small: **one direct dependency** ([`pterm`](https://github.com/pterm/pterm)
for the terminal UI) and the Go standard library for everything else. Most
accepted contributions are new detection signatures, new passive sources, bug
fixes, and tests.

By contributing you agree your work is licensed under the project's
[MIT License](LICENSE) and that you follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security first

**Never open a public issue or pull request for a security vulnerability.**
Use [private reporting](SECURITY.md) instead.

NexProwl is a security tool for **authorized** testing. Contributions that only
make sense for unauthorized scanning, or that add exploitation rather than
reconnaissance, will be declined. See [Security-sensitive contributions](#security-sensitive-contributions).

## Prerequisites

- **Go 1.24 or newer** (`go.mod` pins the minimum; CI uses `go-version-file`)
- **Git**
- **A C compiler** — only needed for `go test -race` (`gcc` on Linux,
  Xcode command line tools on macOS, MinGW-w64 or TDM-GCC on Windows). Without
  one, `-race` fails with `cgo: C compiler "gcc" not found`; run the plain
  suite locally and let CI cover the race build.
- Optional: [GoReleaser](https://goreleaser.com) v2 to validate release config,
  and Chrome/Chromium if you touch `-screenshot`

No linters or test frameworks beyond the standard toolchain. Do not add any.

## Getting started

```bash
git clone https://github.com/Arseno25/nexprowl.git
cd nexprowl
go build ./...
go test ./...
./nexprowl --help     # or .\nexprowl.exe --help on Windows
```

## Fork and branch workflow

1. Fork the repository on GitHub.
2. Create a topic branch off `main`:
   ```bash
   git checkout main
   git pull upstream main
   git checkout -b feat/vhost-sni-fuzzing
   ```
   Branch names follow the commit type: `feat/`, `fix/`, `docs/`, `test/`,
   `refactor/`, `ci/`, `chore/`.
3. Commit focused changes (see [Commits](#commits)).
4. Push to your fork and open a pull request against `Arseno25/nexprowl:main`.
5. Keep the branch rebased on `main`; resolve conflicts on your side.

Do not commit scan output. `.gitignore` already excludes `results/`, `*.log`,
and the usual local test artifacts — check `git status` before committing
anyway. A recon run's output can identify a client.

## Formatting

`gofmt` is the entire style guide. CI fails if `gofmt -l .` prints anything.

```bash
gofmt -w .
```

Line endings are LF, enforced by `.gitattributes`. On Windows, if `gofmt -l .`
lists files you never touched, your checkout has CRLF endings:

```bash
git config core.autocrlf false
git rm --cached -r . && git reset --hard
```

Match the surrounding code: short receiver names, comments that explain *why*
a non-obvious choice was made, no comment restating the next line.

## Testing

```bash
gofmt -l .                                  # must print nothing
go vet ./...
go test -count=1 ./...
go test -count=1 -race ./...                # needs a C compiler
go test -coverprofile=coverage.out ./...    # project floor: 70%
go tool cover -func=coverage.out | tail -1
```

Rules for tests:

- **Standard library `testing` only.** No assertion libraries, no mocking
  frameworks, no fixtures directory conventions.
- **Never depend on live internet services.** Use `httptest.Server`, `t.TempDir()`,
  the mock resolver pattern in `internal/scanner/context_test.go`, and
  deterministic fixtures. A test that fails when the maintainer is on a plane is
  a broken test.
- **Table-driven** where there is more than one case.
- Anything with a branch, a parser, or a security decision needs a test. Pure
  wiring does not.
- Parsers get their **invalid** inputs tested, not just the happy path.
- Coverage must not drop below 70%. Raising it is welcome.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/):

```
feat(vhost): fuzz SNI in addition to the Host header

The size-model filter caught wildcard noise on Host-header probes but
missed servers that route purely on SNI, so those vhosts never showed up.
```

Types used here: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `ci`,
`build`, `chore`, `style`. Only `feat`, `fix`, and `perf` appear in the release
changelog — the rest are filtered out by `.goreleaser.yaml`.

- Explain **why** in the body; the diff already shows what.
- One logical change per commit. Each commit must build and pass tests on its own.
- Breaking changes: add `!` after the type (`feat(cli)!:`) and a
  `BREAKING CHANGE:` footer describing old behaviour, new behaviour, and
  migration.

## Pull requests

Before opening:

- [ ] `gofmt -l .` prints nothing
- [ ] `go vet ./...` passes
- [ ] `go test -count=1 -race ./...` passes
- [ ] Coverage is at or above 70%
- [ ] No new direct dependency (or the PR justifies why one is unavoidable)
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] Docs updated if the CLI surface changed — the flag must appear in **all
      three** of `internal/config/config.go`, `internal/ui/help.go`, and
      `README.md`

What to expect:

- CI runs format, vet, race tests, the coverage floor, a cross-compile of every
  release target, and `goreleaser check`. All must pass.
- Reviews focus on: does it hold under a hostile response from the scanned host,
  does it honour `ctx`, does it stay in scope, is it tested.
- Small, focused PRs get merged. A PR that reformats unrelated files, bumps
  dependencies as a side quest, or mixes three features will be asked to split.

## Adding to the scanner

The engine runs **targets in parallel** and **modules sequentially per target**,
because modules feed each other: `dns` produces the IPs that `ports` and `vhost`
scan; `sub` produces the hosts `http` probes and the CNAMEs `takeover` inspects.
Modules parallelize internally with their own worker pools.

### A new scan module

Implement `scanner.Module` and register it in `modules.All()` — position in that
slice *is* execution order, so place it after whatever fills the fields it reads.

```go
type MyModule struct{}

func (MyModule) Name() string { return "mine" }

func (MyModule) Run(ctx context.Context, sc *scanner.ScanContext) error {
    sc.Limit(ctx)                          // respect -rate and -jitter
    sc.Found("live", "found %s", host)     // drives the UI counters
    sc.Result.Web = append(sc.Result.Web, ...)
    return nil
}
```

Rules a module must follow:

- Honour `ctx` on **every** network call, and `select` on `ctx.Done()` when
  feeding or draining a job channel.
- Call `sc.Limit(ctx)` before each network operation.
- Size worker pools with `min(sc.Opts.Workers, len(work))`, and take the
  semaphore slot **before** spawning the goroutine, not inside it.
- Close every response body, and read bodies through `io.LimitReader`.
- Respect `sc.InScope(host)` before sending traffic anywhere.
- Return an error only for a real failure. "Nothing found" is `nil` — a `tls`
  module that finds no TLS is not a module error.
- Never report a finding from an ambiguous signal. A DNS timeout is not an
  NXDOMAIN; a failed fetch is not a takeover.

### Signatures

| What | Where | Format |
|------|-------|--------|
| Technology | `internal/detect/signatures.go` | `sig("Name", "regex")` — case-insensitive against headers + body |
| WAF | `internal/detect/signatures.go` | same, headers only |
| CDN | `internal/detect/detect.go` | substring of the `Server` header |
| Takeover | `internal/detect/takeover.go` | `{"suffix.tld", "Service", "unclaimed-page marker"}` |

For a takeover fingerprint, `Suffix` is matched on a label boundary, and the
third field is the lowercase marker the service returns when the name is
dangling. Leave it `""` if the service goes NXDOMAIN instead. Cross-check every
new fingerprint against
[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) and cite
the source in the PR.

### A passive source

Add a `fetch` func in `internal/modules/subdomain.go` and append it to
`passiveSources`. It must be keyless and free (keyed sources are opt-in via
environment variables), wrap the target in `esc()`, and return an error rather
than partial garbage — one dead source must not fail the scan.

## Security-sensitive contributions

Extra scrutiny applies to changes that:

- Touch `-proxy`, `-doh`, `-stealth`, or the rate limiter — a silent fallback to
  direct, unproxied, or unlimited traffic is a serious bug, not a nit
- Weaken TLS verification anywhere outside the scan-probe clients
  (`-webhook` delivery and DoH must stay verified)
- Build a file path, shell argument, or subprocess argument from scanned data
- Increase default scan intensity, add a new default-on active check, or raise
  a default worker count
- Add a new outbound destination the user did not name

Such PRs must explain the threat model in the description and include tests for
the hostile input. "It works on example.com" is not a review.

Do not add: exploitation payloads, credential brute-forcing, DoS amplification,
mass untargeted scanning helpers, or anything whose purpose is evading detection
on systems you have not been authorized to test.

## Releases

Maintainers only. See [docs/RELEASE.md](docs/RELEASE.md).

## Questions

Open a [discussion](https://github.com/Arseno25/nexprowl/discussions) or see
[SUPPORT.md](SUPPORT.md).

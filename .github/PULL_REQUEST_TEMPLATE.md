<!--
Thanks for contributing to NexProwl.
Security vulnerabilities: do not open a PR. See SECURITY.md.
-->

## What this changes

<!-- One or two sentences. The diff shows what; explain why. -->

## Type of change

- [ ] Bug fix (no behaviour change beyond fixing the bug)
- [ ] New feature (module, flag, output format)
- [ ] Detection signature (tech / WAF / CDN / takeover)
- [ ] Passive source
- [ ] Documentation
- [ ] Build / CI / release tooling
- [ ] Breaking change (CLI flag, output schema, or exit code changes)

## Checklist

- [ ] `make check` passes (gofmt, vet, race tests, 70% coverage floor, build)
- [ ] New branches, parsers, and security decisions have tests
- [ ] No new direct dependency was added (or the PR explains why one is unavoidable)
- [ ] Tests do not depend on live third-party services
- [ ] Docs updated (`README.md`, `docs/USAGE.md`, `internal/ui/help.go`) if the CLI surface changed
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`

## Breaking changes

<!-- If you ticked "Breaking change": old behaviour, new behaviour, migration note. Otherwise write "None". -->

None

## Testing performed

<!-- Which commands you ran. Scans must target assets you own or are authorized to test. -->

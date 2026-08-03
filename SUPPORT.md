# Support

NexProwl is a volunteer-maintained open source project. There is no commercial
support, no SLA, and no private help desk.

## Before asking

1. Read the built-in help — it is the authoritative flag reference:
   ```bash
   nexprowl --help
   ```
2. Check [README.md](README.md) and [docs/USAGE.md](docs/USAGE.md).
3. Confirm you are on the latest release:
   ```bash
   nexprowl version
   ```
   Compare against <https://github.com/Arseno25/nexprowl/releases/latest>.
4. Search [existing issues](https://github.com/Arseno25/nexprowl/issues?q=is%3Aissue)
   and [discussions](https://github.com/Arseno25/nexprowl/discussions).

## Where to go

| I want to… | Go here |
|---|---|
| Ask how to do something | [Discussions → Q&A](https://github.com/Arseno25/nexprowl/discussions) |
| Report a bug | [New issue → Bug report](https://github.com/Arseno25/nexprowl/issues/new/choose) |
| Request a feature or signature | [New issue → Feature request](https://github.com/Arseno25/nexprowl/issues/new/choose) |
| Report a **security vulnerability** | [Private advisory](https://github.com/Arseno25/nexprowl/security/advisories/new) — **never a public issue**. See [SECURITY.md](SECURITY.md) |
| Contribute code | [CONTRIBUTING.md](CONTRIBUTING.md) |

## What makes a good question

- The exact command you ran (redact real target names if needed)
- `nexprowl version` output
- What you expected versus what happened
- Error output, ideally captured with `-no-color`
- Your OS, and whether you are behind a proxy, VPN, or restricted DNS

## Common issues

**No results / everything times out.** Your resolver or network is likely
filtering. Try `-doh`, or supply resolvers with `-r resolvers.txt`. Raise
`-timeout` from the 4-second default on slow links.

**Scan feels too aggressive.** Use `-stealth` (workers 10, rate 10, timeout 8s,
passive-only), or tune `-rate` and `-t` directly. Passive-only recon is
`-passive`.

**`-screenshot` does nothing.** NexProwl shells out to an installed
Chrome/Chromium rather than bundling a browser. Install one, or point at it with
`-chrome /path/to/chrome`. Screenshots do not work in the minimal Docker image —
see the [Dockerfile](Dockerfile) notes.

**`gofmt -l .` lists files on Windows.** Your checkout has CRLF line endings.
See the formatting section of [CONTRIBUTING.md](CONTRIBUTING.md).

**Wildcard DNS floods results.** NexProwl detects wildcards and filters
bruteforce hits automatically; check the warning line in the scan log. Narrow
scope with `-exclude`.

## What is out of scope

Maintainers will not help you:

- Scan a system you do not own or have written permission to test
- Bypass a defense on infrastructure that is not yours
- Interpret findings against a specific third-party target
- Build exploitation tooling on top of NexProwl

Requests of this kind are closed without discussion. See the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Response times

Best effort. Issues with a clear reproduction get looked at first. If nobody has
replied in two weeks, a polite bump on the thread is fine.

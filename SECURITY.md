# Security Policy

NexProwl is a reconnaissance tool. Its output frequently contains sensitive
information about the systems you are authorized to test, and its network
behaviour is attributable to you. Security bugs in a tool like this matter, and
we want to hear about them.

## Supported versions

| Version | Supported |
|---------|-----------|
| `0.1.x` (latest release) | Yes — security fixes land here |
| `main` branch | Yes — report anything you find |
| Anything older than the latest release | No |

NexProwl follows semantic versioning from `v0.1.0` onward. Only the most recent
release line receives security fixes. Upgrade before reporting an issue you
found on an older build.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a security
vulnerability.**

Report privately through GitHub's private vulnerability reporting:

1. Go to <https://github.com/Arseno25/nexprowl/security/advisories/new>
2. Fill in the advisory form
3. Submit — only the maintainers can see it

If private vulnerability reporting is unavailable to you, open a public issue
titled `security: request contact` containing **no technical detail** at all,
and a maintainer will arrange a private channel.

There is no published security email address for this project. Do not send
vulnerability details to any address claiming to be one.

## What to include

A good report contains:

- Affected version (`nexprowl version` output) and platform
- The exact command line that triggers the issue
- A minimal reproduction — prefer `example.com`, a container, or a local lab
  host over a real third-party target
- What an attacker gains: code execution, file overwrite outside the output
  directory, credential or scan-result disclosure, denial of service, etc.
- Any crash output, stack trace, or malformed input file needed to reproduce
- Whether the issue is already public anywhere

Redact real customer, client, or bug-bounty-target data before sending. If a
reproduction genuinely requires a real hostname, say so and we will work out a
sanitised variant.

## Response process

| Stage | Target |
|-------|--------|
| Acknowledge the report | 5 business days |
| Initial assessment (valid / not / severity) | 10 business days |
| Fix and released patch for confirmed issues | 90 days, sooner for high severity |
| Public advisory and credit | On release of the fix |

This is a volunteer-maintained project, not a vendor with an on-call rotation.
These targets are what we aim for, not a contractual SLA. If you have not heard
back within the acknowledgement window, please ping the advisory thread.

## Coordinated disclosure

Please give us a chance to ship a fix before going public. Do not disclose the
vulnerability publicly — blog post, conference talk, tweet, exploit release, or
public issue — before either the fix is released or 90 days have passed since
your report, whichever comes first. If you intend to publish on a specific date,
tell us in the initial report so we can plan around it.

We will credit you in the advisory and the changelog unless you ask us not to.

## Out of scope

The following are working as designed and are not vulnerabilities:

- **Certificate verification is disabled for scan traffic.** The `http`, `tls`,
  and `vhost` modules intentionally accept expired, self-signed, and
  hostname-mismatched certificates, because reporting on broken TLS is the
  point of the `tls` module. Verification is *not* disabled for anything else —
  notably `-webhook` delivery, which uses a normal verified client.
- **NexProwl sends traffic to the target you specify.** Port scanning, virtual
  host fuzzing, AXFR attempts, and crawling are the product. Using them without
  authorization is your responsibility, not a tool vulnerability.
- **Scan results are written world-readable (`0644`).** Output goes where you
  point `-o`. If results are sensitive, write them to a directory with
  restrictive permissions, or an encrypted volume.
- **Passive-source API keys are read from environment variables**
  (`NEXPROWL_SECURITYTRAILS_KEY` and friends). Anything that can read your
  environment can read those keys; that is inherent to the mechanism.
- Missing hardening in a third-party service NexProwl queries.
- Vulnerabilities that require an attacker to already control the machine
  running NexProwl.

## In scope — things we definitely want to hear about

- Remote input (a DNS response, HTTP response, certificate, crawled page,
  webhook reply) causing a panic, hang, memory exhaustion, or code execution
- Writing files outside the path given to `-o`, or overwriting unrelated files
- Scan results, API keys, or environment data leaking to an unintended host
- The `-proxy`, `-doh`, or `-stealth` paths silently falling back to direct,
  unproxied, or unrate-limited traffic
- Command injection through any value derived from a scan target, including the
  Chrome invocation used by `-screenshot`
- Any bypass of the `-include` / `-exclude` scope enforcement that causes
  NexProwl to send traffic to a host you never authorized

## Legal note for researchers

Testing NexProwl itself against your own machines, containers, and lab
infrastructure is welcome. Do not use a NexProwl bug as a pretext to scan third
parties: we will not accept reports whose reproduction steps require attacking
systems you do not own or have written permission to test.

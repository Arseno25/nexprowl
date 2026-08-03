# Packaging templates

Templates for distribution channels that are **not published yet**. Channels
that *are* live are not here, because nothing about them is hand-maintained.

## What ships today

| Channel | How it is produced | Maintenance |
|---|---|---|
| `go install` | the module path itself | none |
| Clone and `make install` | [`Makefile`](../Makefile) | none |
| Release archives | `archives:` in [`.goreleaser.yaml`](../.goreleaser.yaml) | none |
| `.deb` / `.rpm` | `nfpms:` in `.goreleaser.yaml`, attached to each release | none |
| Docker | [`Dockerfile`](../Dockerfile), built by the user | none |

Every one of these is produced by the tag push and needs no external
repository, credential, or hosted service. That is the bar a new channel has to
clear before it is worth adding.

## Scoop (Windows) — not published

[`scoop/nexprowl.json`](scoop/nexprowl.json) is a complete manifest with three
placeholder values.

1. Download `checksums.txt` from the [release](https://github.com/Arseno25/nexprowl/releases/latest).
2. Replace in the manifest:
   - `REPLACE_WITH_VERSION` → the version **without** a leading `v`, e.g. `0.1.0`
     (the `vREPLACE_WITH_VERSION` occurrences in the URLs become `v0.1.0`)
   - `REPLACE_WITH_SHA256_FROM_CHECKSUMS_TXT` → the hash for the matching
     `nexprowl_<version>_windows_<arch>.zip` line
3. Validate locally:
   ```powershell
   scoop install .\packaging\scoop\nexprowl.json
   nexprowl version
   scoop uninstall nexprowl
   ```
4. Publish by creating a bucket repository named `scoop-bucket` under the same
   owner and committing the manifest to `bucket/nexprowl.json`. Users then run:
   ```powershell
   scoop bucket add nexprowl https://github.com/Arseno25/scoop-bucket
   scoop install nexprowl
   ```

The `checkver` and `autoupdate` blocks are wired to the GitHub releases feed, so
later versions update without editing hashes by hand.

**Better option:** GoReleaser has a `scoops:` block that maintains the bucket
automatically, exactly like the Homebrew cask. Once `Arseno25/scoop-bucket`
exists, add that block and delete this template rather than maintaining a
manifest by hand.

## Not configured

Each of these needs infrastructure or a long-lived credential that has to keep
working after the release is over. None is set up, and the README does not claim
otherwise.

- **Homebrew tap** — GoReleaser has a `homebrew_casks:` block. Needs a second
  repository (`homebrew-tap`) and a PAT that can write to it, since the built-in
  `GITHUB_TOKEN` cannot push across repositories. Worth noting: a cask can clear
  the macOS Gatekeeper quarantine flag on install, which is the cheapest fix for
  that problem short of Apple notarization.
- **Hosted APT / DNF repositories** — the `.deb` and `.rpm` files exist, but
  serving them as a repository means holding a GPG signing key in CI. That key
  vouches for packages installed as root on every subscriber's machine; losing
  or leaking it is a serious incident, and every existing installation has to
  re-import by hand if it is rotated. Not something to set up casually.
- **GHCR container image** — the `Dockerfile` works, but nothing pushes it to a
  registry. Would be a `dockers:` block plus `packages: write` permission.
- **AUR** — GoReleaser has an `aurs:` block. Needs an AUR account and an SSH
  private key stored as a repository secret.
- **Distribution-official packages** (Debian, Ubuntu, Fedora, Kali, Arch
  community) — these require a distribution maintainer to sponsor the package.
  Not something this repository can configure. Do not claim NexProwl is packaged
  for any distribution until it actually is.

# Packaging templates

Templates for distribution channels that are **not published yet**. Channels
that *are* live are not here, because nothing about them is hand-maintained.

## Already published — do not add templates for these

| Channel | How it is produced |
|---|---|
| Homebrew tap | `homebrew_casks:` in [`.goreleaser.yaml`](../.goreleaser.yaml) — GoReleaser commits the cask to `Arseno25/homebrew-tap` on every release |
| `.deb` / `.rpm` | `nfpms:` in `.goreleaser.yaml`, attached to each release |
| APT repository | [`.github/workflows/apt-repo.yml`](../.github/workflows/apt-repo.yml) — signs and publishes to GitHub Pages |
| Docker | [`Dockerfile`](../Dockerfile) in the repository root |
| `go install` | the module path itself |

Setup steps for the maintainer live in
[docs/GITHUB_SETUP.md](../docs/GITHUB_SETUP.md#8-distribution-channels).

If you find yourself editing a Homebrew formula by hand, stop — it is generated,
and your edit will be overwritten on the next release. Change the
`homebrew_casks:` block instead.

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

- **GHCR container image** — the `Dockerfile` works, but nothing pushes it to a
  registry. Would be a `dockers:` block plus `packages: write` permission.
- **Hosted DNF/YUM repository** — `.rpm` files are published, but there is no
  repository to `dnf install` from. Would mirror the APT workflow using
  `createrepo_c` and RPM GPG signing.
- **AUR** — GoReleaser has an `aurs:` block. Needs an AUR account and an SSH
  private key stored as a repository secret.
- **Distribution-official packages** (Debian, Ubuntu, Fedora, Kali, Arch
  community) — these require a distribution maintainer to sponsor the package.
  Not something this repository can configure. Do not claim NexProwl is packaged
  for any distribution until it actually is.

# Packaging templates

**Nothing in this directory is published yet.** These are unfilled templates for
distribution channels on the [roadmap](../README.md#roadmap). The only supported
install methods today are `go install`, the GitHub Release archives, building
from source, and the `Dockerfile` in the repository root.

Every template needs a published GitHub Release before it can be completed —
the URLs and SHA-256 hashes come from that release's `checksums.txt`.

## Scoop (Windows)

[`scoop/nexprowl.json`](scoop/nexprowl.json) is a complete manifest with three
placeholder values.

1. Publish the release (see [docs/RELEASE.md](../docs/RELEASE.md)).
2. Download `checksums.txt` from the release page.
3. Replace in the manifest:
   - `REPLACE_WITH_VERSION` → the version **without** a leading `v`, e.g. `0.1.0`
     (the `vREPLACE_WITH_VERSION` occurrences in the URLs become `v0.1.0`)
   - `REPLACE_WITH_SHA256_FROM_CHECKSUMS_TXT` → the hash for the matching
     `nexprowl_<version>_windows_<arch>.zip` line
4. Validate locally before publishing:
   ```powershell
   scoop install .\packaging\scoop\nexprowl.json
   nexprowl version
   scoop uninstall nexprowl
   ```
5. Publish by creating a bucket repository named `scoop-bucket` under the same
   owner and committing the manifest to `bucket/nexprowl.json`. Users then run:
   ```powershell
   scoop bucket add nexprowl https://github.com/Arseno25/scoop-bucket
   scoop install nexprowl
   ```

The `checkver` and `autoupdate` blocks are already wired to the GitHub releases
feed, so later versions update without editing hashes by hand.

## Homebrew (macOS / Linux)

[`homebrew/nexprowl.rb`](homebrew/nexprowl.rb) is a tap formula template.

Two ways to ship it:

**Manual tap.** Create a repository named `homebrew-tap` under the same owner,
fill the placeholders in the formula from `checksums.txt`, and commit it to
`Formula/nexprowl.rb`. Users then run:

```bash
brew tap Arseno25/tap
brew install nexprowl
```

**Let GoReleaser maintain it.** Once the tap repository exists, add a `brews:`
block to `.goreleaser.yaml` and GoReleaser will open the formula update on every
release, so the checked-in template becomes unnecessary. This needs a personal
access token with write access to the tap repository, stored as a repository
secret — the default `GITHUB_TOKEN` cannot push to another repository.

Do not submit NexProwl to homebrew-core. Core has notability requirements and
rejects most security tooling; a tap is the correct channel.

## Docker

Docker is **not** a template — the [`Dockerfile`](../Dockerfile) in the
repository root is real and works today:

```bash
docker build -t nexprowl:dev .
docker run --rm nexprowl:dev version
docker run --rm -v "$PWD/results:/results" nexprowl:dev example.com
```

Publishing it to a registry (GHCR) is on the roadmap and would be wired through
GoReleaser's `dockers:` block. Note the screenshot limitation documented at the
bottom of the `Dockerfile`.

## Linux distributions

`.deb` and `.rpm` packages via GoReleaser's `nfpms:` block, and an AUR package,
are on the roadmap. Neither is configured. Do not claim NexProwl is packaged for
Kali, Debian, Arch, or any distribution — it is not.

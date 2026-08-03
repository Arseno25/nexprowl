# Release process

Maintainers only. Releases are cut by pushing a `v*` tag; everything after that
is automated by [`.github/workflows/release.yml`](../.github/workflows/release.yml)
and [`.goreleaser.yaml`](../.goreleaser.yaml).

## What the tag triggers

1. **Validate** job — `gofmt`, `go vet`, `go test -race`, `go build`.
2. **GoReleaser** job — cross-compiles six targets with `CGO_ENABLED=0`, builds
   archives, generates `checksums.txt` (SHA-256), builds the changelog from
   commits since the previous tag, and publishes a GitHub Release.

The workflow only has `contents: write` on the release job and uses the built-in
`GITHUB_TOKEN`. No secrets to configure.

Nothing is published until the tag is pushed. A tag that fails validation
produces no release.

## Pre-flight

```bash
git checkout main
git pull
go mod tidy
gofmt -l .            # must print nothing
go vet ./...
go test -race ./...
go build ./...
```

If GoReleaser is installed locally, dry-run the whole release first:

```bash
goreleaser check
goreleaser release --snapshot --clean
ls -la dist/
```

`--snapshot` never touches GitHub. Inspect `dist/` and smoke-test one binary:

```bash
tar -tzf dist/nexprowl_*_linux_amd64.tar.gz
./dist/nexprowl_linux_amd64_v1/nexprowl version
```

Then finish the checklist:

- [ ] `CHANGELOG.md` — move `## [Unreleased]` content into a new version section
      and add the release date (`## [0.1.0] - 2026-01-15`)
- [ ] `CHANGELOG.md` — update the link definitions at the bottom
- [ ] `docs/releases/vX.Y.Z.md` exists and the draft banner is removed
- [ ] README install snippets reference the version being released, if any pin it
- [ ] Working tree is clean and pushed

Commit the changelog before tagging — the tag must point at the commit that
contains it.

## Cut the release

```bash
git checkout main
git pull
go mod tidy
go fmt ./...
go vet ./...
go test -race ./...

git tag -a v0.1.0 -m "NexProwl v0.1.0"
git push origin v0.1.0
```

Pushing the tag starts the release workflow. Watch it at
<https://github.com/Arseno25/nexprowl/actions>.

Tags are `vMAJOR.MINOR.PATCH`. GoReleaser strips the leading `v`, so the tag
`v0.1.0` produces `nexprowl_0.1.0_linux_amd64.tar.gz` and `nexprowl version`
reports `NexProwl 0.1.0`. A tag with a pre-release suffix (`v0.2.0-rc.1`) is
marked as a GitHub pre-release automatically (`prerelease: auto`).

## Fixing a bad tag

**Before the workflow finishes** — cancel the run first, or you will race it.

Delete a local tag:

```bash
git tag -d v0.1.0
```

Delete a remote tag:

```bash
git push origin :refs/tags/v0.1.0
# equivalently
git push --delete origin v0.1.0
```

If a release was already published, delete it too — a leftover release keeps the
tag alive on GitHub:

```bash
gh release delete v0.1.0 --yes --cleanup-tag
```

Then fix the problem, commit, and tag again.

**Never re-point a tag that people may have downloaded.** Go module proxies and
checksum databases cache `github.com/Arseno25/nexprowl@v0.1.0` permanently; if a
published tag moves, `go install` fails for everyone with a checksum mismatch.
If a tag has been public for more than a few minutes, burn it and ship the next
patch version instead.

## Verifying the published release

Download the archive and `checksums.txt` from the release page.

Linux / macOS:

```bash
sha256sum -c checksums.txt --ignore-missing
```

Windows PowerShell:

```powershell
(Get-FileHash .\nexprowl_0.1.0_windows_amd64.zip -Algorithm SHA256).Hash.ToLower()
Select-String -Path .\checksums.txt -Pattern 'windows_amd64'
```

Compare the two strings.

## Testing release artifacts

Do this before announcing anything:

```bash
# 1. The archive extracts and the binary runs
tar -xzf nexprowl_0.1.0_linux_amd64.tar.gz
./nexprowl version          # version, commit, and date must NOT say dev/none/unknown
./nexprowl --help

# 2. go install resolves the new tag
#    (the proxy can lag a few minutes after the tag is pushed)
GOBIN=/tmp/nexprowl-test go install github.com/Arseno25/nexprowl@v0.1.0
/tmp/nexprowl-test/nexprowl version

# 3. A real scan against an authorized target still works
./nexprowl example.com -m dns -silent
```

If `nexprowl version` reports `dev` / `none` / `unknown` from a release archive,
the linker flags did not apply. Check that the `-X` paths in `.goreleaser.yaml`
still match the variable locations — `TestVersionLinkerFlags` in `main_test.go`
pins them.

## Release notes

GoReleaser generates the changelog from commit subjects since the previous tag,
grouped into Features / Bug fixes / Performance / Other, with `docs:`, `test:`,
`ci:`, `chore:`, `style:`, `build:`, `refactor:`, and merge commits filtered out.
The `release.footer` in `.goreleaser.yaml` appends checksum instructions and the
authorized-use notice.

For a significant release, write a longer narrative in `docs/releases/vX.Y.Z.md`
first (see [`docs/releases/v0.1.0.md`](releases/v0.1.0.md) for the shape), then
paste it into the top of the generated release body on GitHub. `mode: append` in
the release config means hand-written body text added before the workflow runs is
preserved.

Good release notes lead with what changed for the user, call out breaking
changes and their migration path explicitly, and never claim a distribution
channel that does not exist yet.

## Patch release

For a fix on top of a published release:

```bash
git checkout main
git pull
# merge the fix as normal, then:
```

Move the fix into a new `## [0.1.1]` section in `CHANGELOG.md` with today's
date, commit, and tag:

```bash
git tag -a v0.1.1 -m "NexProwl v0.1.1"
git push origin v0.1.1
```

If `main` has already moved on with features that should not ship in a patch,
branch from the release tag instead:

```bash
git checkout -b release/0.1.x v0.1.0
git cherry-pick <fix-commit>
git tag -a v0.1.1 -m "NexProwl v0.1.1"
git push origin release/0.1.x v0.1.1
```

The release workflow triggers on the tag regardless of which branch it points at.
Remember to forward-port the fix to `main` afterwards.

## Version numbering

- **Patch** (`0.1.0` → `0.1.1`) — bug fixes, new detection signatures, docs
- **Minor** (`0.1.0` → `0.2.0`) — new modules, new flags, new output formats
- **Major / pre-1.0 minor** — anything that changes existing flag behaviour, the
  JSON output schema, or exit codes

While the project is `0.x`, breaking changes go in a **minor** bump and must be
documented in `CHANGELOG.md` with old behaviour, new behaviour, and a migration
note.

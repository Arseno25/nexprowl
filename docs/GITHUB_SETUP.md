# GitHub repository setup

Manual steps for the repository owner. **None of this can be done from code** —
these are GitHub settings, and they must be applied through the web UI or the
`gh` CLI. This file exists so the configuration is written down and repeatable,
not so it can be automated from the repository.

Work through it once before announcing `v0.1.0`.

---

## 1. Description and topics

**Settings → General**, or the ⚙️ next to *About* on the repository home page.

Description:

```
A fast, single-binary reconnaissance engine for DNS, subdomains, ports, HTTP, TLS, virtual hosts, takeovers, and crawling.
```

Website: leave empty, or point at the latest release.

Topics:

```
cybersecurity
reconnaissance
bug-bounty
pentesting
subdomain-enumeration
port-scanner
dns-recon
takeover-detection
web-security
golang
security-tools
```

Also tick **Releases** and **Packages** under *Include in the home page*, and
untick **Deployments** (unused).

With the `gh` CLI:

```bash
gh repo edit Arseno25/nexprowl \
  --description "A fast, single-binary reconnaissance engine for DNS, subdomains, ports, HTTP, TLS, virtual hosts, takeovers, and crawling." \
  --add-topic cybersecurity \
  --add-topic reconnaissance \
  --add-topic bug-bounty \
  --add-topic pentesting \
  --add-topic subdomain-enumeration \
  --add-topic port-scanner \
  --add-topic dns-recon \
  --add-topic takeover-detection \
  --add-topic web-security \
  --add-topic golang \
  --add-topic security-tools
```

## 2. Social preview image

**Settings → General → Social preview → Edit → Upload an image.**

This is the card that renders when the repository is linked on social media,
Slack, or Discord. Without it, GitHub falls back to a generic avatar card.

- **1280 × 640 px**, PNG or JPG, under 1 MB
- Safe area: keep text within the middle ~1100 × 500 px — the edges get cropped
  at some aspect ratios
- Include: the NexProwl name, the one-line description, and the logo from
  `assets/logo.svg`
- Keep it legible at thumbnail size; a screenshot of a terminal is not

## 3. Enable Discussions

**Settings → General → Features → Discussions → Set up discussions.**

Required: `.github/ISSUE_TEMPLATE/config.yml` and `SUPPORT.md` both link to the
discussions page. Until it is enabled, those links 404.

Suggested categories (delete the defaults you will not use):

| Category | Format | Purpose |
|---|---|---|
| Q&A | Question / answer | Usage help — keeps the issue tracker for defects |
| Ideas | Open discussion | Feature and signature proposals before an issue |
| Show and tell | Open discussion | Pipelines, integrations, workflows |
| Announcements | Announcement (maintainers post) | Releases |

## 4. Enable private vulnerability reporting

**Settings → Advanced Security (or Security & analysis) → Private vulnerability
reporting → Enable.**

Required: `SECURITY.md`, `CODE_OF_CONDUCT.md`, and the issue template
`config.yml` all direct reporters to
`https://github.com/Arseno25/nexprowl/security/advisories/new`. That URL only
works once this is on. For a security tool this is not optional — without it,
the only reporting channel is a public issue.

## 5. Enable Dependabot and secret scanning

**Settings → Advanced Security (or Security & analysis).** Enable:

- **Dependency graph** — prerequisite for the rest
- **Dependabot alerts** — CVEs in `pterm` and its transitive dependencies
- **Dependabot security updates** — automatic PRs for vulnerable dependencies
- **Secret scanning** — free on public repositories
- **Push protection** — blocks a commit that contains a detected credential
  before it reaches the remote. Enable it: this repository's own docs tell users
  to put API keys in environment variables, and a pasted key in a test fixture
  is a realistic accident.
- **Code scanning (CodeQL)** — optional but recommended. Use the default setup;
  it adds a Go analysis workflow without a config file to maintain.

Version-update PRs (weekly Go modules, GitHub Actions, and Docker) are already
configured in `.github/dependabot.yml` and start once the dependency graph is on.

## 6. Branch protection for `main`

**Settings → Rules → Rulesets → New branch ruleset** (rulesets are the current
mechanism; classic *Branches → Add rule* works too).

- Name: `main`
- Enforcement status: **Active**
- Target branches: **Include default branch**

Enable these rules:

| Rule | Setting |
|---|---|
| Restrict deletions | On |
| **Block force pushes** | On |
| Require a pull request before merging | On — 1 approval (see note below) |
| Dismiss stale approvals on new commits | On |
| Require status checks to pass | On — see the list below |
| Require branches to be up to date before merging | On |
| Require linear history | On (optional, keeps `git log` readable) |
| Require conversation resolution before merging | On |

Required status checks — the job names from `.github/workflows/ci.yml`:

```
Test
Cross-compile
GoReleaser config
```

These only appear in the picker after each job has run at least once on the
repository, so push a PR first, then come back and select them.

> **Solo maintainer note.** If you are the only maintainer, requiring 1 approval
> blocks you from merging your own PRs. Either add yourself to a bypass list
> (Ruleset → *Bypass list* → your account), or set approvals to 0 and keep the
> status-check requirement — the CI gate is the part that catches real problems.
> Do **not** disable "Block force pushes" to work around it.

Do not exempt tags from protection: **Rules → Rulesets → New tag ruleset**,
target `v*`, enable *Restrict deletions* and *Block force pushes*, so a released
tag cannot be silently moved. See the warning in
[docs/RELEASE.md](RELEASE.md#fixing-a-bad-tag) about why a moved tag breaks
`go install` permanently.

## 7. Actions permissions

**Settings → Actions → General.**

- Actions permissions: *Allow all actions and reusable workflows*, or the
  stricter *Allow ... and select non-{owner} actions* with
  `goreleaser/goreleaser-action@*` and `actions/*` allowed
- **Workflow permissions: Read repository contents and packages permissions**
  (the restrictive default). Both workflows declare the permissions they need at
  the job level; the release job asks for `contents: write` explicitly
- Tick **Allow GitHub Actions to create and approve pull requests** only if you
  later add automation that opens PRs

## 8. Distribution channels

Two channels need one-time setup before a release can publish to them. Both are
driven by `.goreleaser.yaml` and `.github/workflows/apt-repo.yml`; neither can
be configured from code.

### 8a. Homebrew tap

GoReleaser commits the cask to a separate repository on every release.

1. Create a **public** repository named exactly **`homebrew-tap`** under the
   same owner. The `homebrew-` prefix is what lets users write
   `brew install Arseno25/tap/nexprowl` instead of the full repository name.
   ```bash
   gh repo create Arseno25/homebrew-tap --public \
     --description "Homebrew tap for Arseno25's tools"
   ```
2. Give it an initial commit on `main` — GoReleaser pushes to an existing
   branch, it does not create the repository or an unborn branch:
   ```bash
   gh repo clone Arseno25/homebrew-tap /tmp/tap && cd /tmp/tap
   printf '# homebrew-tap\n\n```bash\nbrew install Arseno25/tap/nexprowl\n```\n' > README.md
   git add README.md && git commit -m "chore: initial commit" && git push
   ```
3. Confirm the **`GIT_TOKEN`** secret's PAT has write access to
   `homebrew-tap`, not just to `nexprowl`. The built-in `GITHUB_TOKEN` cannot
   push to another repository, which is the whole reason a PAT is involved.
   A fine-grained token scoped to exactly these two repositories with
   `Contents: read and write` is enough — do not use a classic token with
   full `repo` scope if you can avoid it.

Verify after the next release:

```bash
brew install Arseno25/tap/nexprowl
nexprowl version
brew uninstall nexprowl
```

### 8b. APT repository on GitHub Pages

`.github/workflows/apt-repo.yml` builds a signed APT repository from the `.deb`
artifacts and commits it to the `gh-pages` branch. It needs a GPG key and Pages
enabled.

**Generate a signing key.** Use a dedicated key, not your personal one — it
lives in CI and signs on every release.

```bash
gpg --batch --quick-generate-key "NexProwl APT Repository <noreply@nexprowl.invalid>" rsa4096 sign never
```

That prompts once for a passphrase. Then export it:

```bash
keyid="$(gpg --list-secret-keys --with-colons | awk -F: '/^sec:/ {print $5; exit}')"
gpg --armor --export-secret-keys "$keyid" > /tmp/apt-private.asc
```

**Add the secrets:**

```bash
gh secret set APT_GPG_PRIVATE_KEY --repo Arseno25/nexprowl < /tmp/apt-private.asc
gh secret set APT_GPG_PASSPHRASE  --repo Arseno25/nexprowl   # paste when prompted
shred -u /tmp/apt-private.asc      # or: rm -P on macOS
```

Back up the key somewhere offline. If it is lost, every existing installation
has to re-import a new key by hand.

**Create the `gh-pages` branch** with no history from `main`:

```bash
git checkout --orphan gh-pages
git rm -rf . >/dev/null
printf 'NexProwl APT repository. Generated by .github/workflows/apt-repo.yml — do not edit by hand.\n' > README.md
touch .nojekyll
git add README.md .nojekyll
git commit -m "chore: initialise gh-pages"
git push origin gh-pages
git checkout main
```

**Enable Pages:** Settings → Pages → Source: **Deploy from a branch** → branch
`gh-pages`, folder `/ (root)` → Save.

**Publish:** the workflow runs automatically when the next release is
published. To publish from releases that already exist, trigger it manually:

```bash
gh workflow run apt-repo.yml --repo Arseno25/nexprowl -f rebuild_all=true
```

**Verify** on a Debian or Ubuntu box, or in a container:

```bash
docker run --rm -it debian:12 bash -c '
  apt update && apt install -y curl gnupg
  curl -fsSL https://arseno25.github.io/nexprowl/apt/nexprowl-archive-keyring.gpg \
    > /usr/share/keyrings/nexprowl-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/nexprowl-archive-keyring.gpg] https://arseno25.github.io/nexprowl/apt stable main" \
    > /etc/apt/sources.list.d/nexprowl.list
  apt update && apt install -y nexprowl && nexprowl version'
```

An `apt update` that reports `NO_PUBKEY` or `not signed` means the key export
or the signing step failed — check the workflow log before announcing it.

> **Known limitation.** The `.deb` files live in the `gh-pages` branch, so the
> repository grows by roughly 8 MB per release and that history is permanent.
> Fine for a long while; if it ever matters, move the pool to release assets or
> object storage and keep only the indices in Pages.

## 9. Releases

Nothing to configure — pushing a `v*` tag runs
`.github/workflows/release.yml`. See [docs/RELEASE.md](RELEASE.md).

Optionally, after the first release: **Releases → the release → Set as the
latest release** (GoReleaser does this automatically), and pin the repository to
your profile.

## 10. Optional

- **Settings → General → Pull Requests**: tick *Automatically delete head
  branches* to keep the branch list clean
- **Settings → General → Features**: untick *Wikis* and *Projects* if unused —
  an empty wiki is a dead link on the repository nav
- **Insights → Community Standards**: confirms `README`, `LICENSE`,
  `CONTRIBUTING`, `CODE_OF_CONDUCT`, `SECURITY`, and issue/PR templates are all
  detected. All six ship in this repository; the page should read 100%

---

## Checklist

- [ ] Description set
- [ ] All 11 topics added
- [ ] Social preview image uploaded (1280 × 640)
- [ ] Discussions enabled with Q&A and Ideas categories
- [ ] Private vulnerability reporting enabled
- [ ] Dependency graph, Dependabot alerts, and security updates enabled
- [ ] Secret scanning and push protection enabled
- [ ] Branch ruleset on `main`: force pushes blocked, deletions restricted, CI
      required
- [ ] Tag ruleset on `v*`: force pushes and deletions blocked
- [ ] Workflow permissions set to read-only by default
- [ ] Community Standards page reads 100%

Distribution channels:

- [ ] `Arseno25/homebrew-tap` repository created, public, with an initial
      commit on `main`
- [ ] `GIT_TOKEN` PAT has write access to `homebrew-tap` as well as `nexprowl`
- [ ] `brew install Arseno25/tap/nexprowl` verified after a release
- [ ] Dedicated APT signing key generated and backed up offline
- [ ] `APT_GPG_PRIVATE_KEY` and `APT_GPG_PASSPHRASE` secrets added
- [ ] `gh-pages` orphan branch created
- [ ] GitHub Pages enabled from `gh-pages` / root
- [ ] `apt install nexprowl` verified in a clean Debian container

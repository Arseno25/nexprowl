# Recording the demo

The README references `docs/assets/nexprowl-demo.gif`. That file does not exist
yet and is not committed — this document is the recipe for producing it.

Until it is recorded, the README's demo section stays as a placeholder. Do not
commit a stand-in GIF.

## Rules for the recording

**Only scan targets you are authorized to scan.** A demo is published; a demo
scanning someone else's infrastructure is a published record of unauthorized
scanning.

Use one of:

- **`example.com`** — reserved by IANA (RFC 2606) for documentation. Safe for a
  handful of light requests. Do not record a 10,000-port scan or a full
  bruteforce against it.
- **A local lab** — `localhost`, a Docker host, or a VM you own. Best option for
  the port scanning and HTTP probe segments, since you control what is open and
  the results are reproducible.
- **A domain you own.**

Never record against a bug bounty target, a client, or a real company's
infrastructure, even one you are authorized to test. Authorization does not
extend to publishing their attack surface.

## What to show

Keep it under 90 seconds. The point is the UI and the workflow, not a complete
scan.

| # | Segment | Command | Notes |
|---|---|---|---|
| 1 | Version | `nexprowl version` | Establishes the build being demoed |
| 2 | Help | `nexprowl --help` | Scroll slowly through the module list, then cut |
| 3 | Basic recon | `nexprowl example.com -m dns,tls` | Fast, low-noise, shows the live UI |
| 4 | Module selection | `nexprowl example.com -m sub,http -passive` | Passive keeps it quiet and quick |
| 5 | JSON output | `nexprowl example.com -m dns -o demo.json && jq '.dns' demo.json` | Shows the machine-readable path |
| 6 | HTML report | `nexprowl example.com -m dns,tls -o demo.html` | Say the report opens in a browser; do not record the browser |
| 7 | Pipeline | `echo example.com \| nexprowl -silent -emit urls` | STDIN in, one finding per line out |
| 8 | Run history + diff | `nexprowl example.com -m dns -o runs/` twice, then `nexprowl diff runs/<OLD> runs/<NEW>` | Mention exit code 3 on change |

Trim dead time between segments in post rather than waiting on camera. If a
scan is slow, use `-m dns` or `-passive` — nobody needs to watch a port scan
finish.

## Before recording

```bash
go build -trimpath -o nexprowl .
```

- Terminal size **100 × 30** — wider gets illegible when GitHub scales the GIF
  into the README column
- Dark background, a font with good box-drawing glyph coverage (JetBrains Mono,
  Cascadia Code, Fira Code); NexProwl's UI uses box characters and colour
- **Clear your environment first.** `NEXPROWL_SECURITYTRAILS_KEY` and friends
  must not appear in a recorded `env` or shell prompt
- Use a clean shell with a minimal prompt — no username, hostname, or full paths
  that identify your machine
- Work in a temporary directory so no unrelated files show in `ls`
- Delete `results/` between takes so run history starts clean

## Option A: VHS (recommended)

[VHS](https://github.com/charmbracelet/vhs) records from a script, so the demo
is reproducible and re-recordable after a UI change. That is worth the setup.

Install:

```bash
go install github.com/charmbracelet/vhs@latest
# also needs ttyd and ffmpeg
```

Save as `docs/demo.tape`:

```tape
Output docs/assets/nexprowl-demo.gif

Set FontSize 15
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

Type "nexprowl version"       Enter    Sleep 2s
Type "clear"                  Enter    Sleep 500ms

Type "nexprowl --help"        Enter    Sleep 4s
Type "clear"                  Enter    Sleep 500ms

Type "nexprowl example.com -m dns,tls"   Enter   Sleep 12s
Type "clear"                  Enter    Sleep 500ms

Type "nexprowl example.com -m dns -o demo.json"   Enter   Sleep 10s
Type "jq '.dns.a' demo.json"  Enter    Sleep 3s
Type "clear"                  Enter    Sleep 500ms

Type "echo example.com | nexprowl -silent -emit urls"   Enter   Sleep 10s
Sleep 3s
```

Record:

```bash
vhs docs/demo.tape
```

Tune the `Sleep` durations to your network — a sleep that ends before the scan
does produces a GIF of a truncated scan.

## Option B: asciinema

Best when you want a copy-pasteable, text-based recording rather than a GIF.

```bash
asciinema rec nexprowl-demo.cast --cols 100 --rows 30 --idle-time-limit 2
# run the segments, then Ctrl-D
asciinema play nexprowl-demo.cast     # review before publishing
```

Convert to a GIF with [agg](https://github.com/asciinema/agg):

```bash
agg --font-size 15 --theme monokai nexprowl-demo.cast docs/assets/nexprowl-demo.gif
```

`--idle-time-limit 2` collapses long waits automatically, which suits a scan
demo well.

## Option C: Terminalizer

```bash
npm install -g terminalizer
terminalizer record nexprowl-demo
# edit nexprowl-demo.yml to trim frames and set the theme
terminalizer render nexprowl-demo -o docs/assets/nexprowl-demo.gif
```

Terminalizer's YAML lets you delete individual frames after the fact, which is
the easiest way to cut a slow scan without re-recording. Its default output is
large — check the file size.

## Before committing the GIF

- [ ] **Under 5 MB.** GitHub renders larger files but README load time suffers.
      Reduce with `gifsicle -O3 --lossy=80 --colors 128 in.gif -o out.gif`
- [ ] Readable at the width GitHub renders a README image (~880 px)
- [ ] No API keys, tokens, hostnames, IP addresses, usernames, or file paths
      that identify you or a third party — **watch the whole thing back frame by
      frame**
- [ ] No target other than `example.com` or your own lab
- [ ] Commit to `docs/assets/nexprowl-demo.gif`
- [ ] Commit `docs/demo.tape` too if you used VHS, so the next person can
      re-record it
- [ ] Replace the placeholder block in `README.md` with the image

Then add it to the README:

```markdown
<img src="docs/assets/nexprowl-demo.gif" alt="NexProwl scanning example.com" width="880"/>
```

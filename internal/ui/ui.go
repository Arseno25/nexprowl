// Package ui renders dscan's terminal interface: gradient banner,
// animated live-stats line, finding feed, and summary panels.
package ui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pterm/pterm"

	"dscan/internal/scanner"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

var levelColor = map[scanner.Level]func(a ...any) string{
	scanner.LevelInfo:    pterm.NewRGB(160, 160, 180).Sprint,
	scanner.LevelSuccess: pterm.NewRGB(105, 240, 174).Sprint,
	scanner.LevelWarn:    pterm.NewRGB(255, 214, 90).Sprint,
	scanner.LevelError:   pterm.NewRGB(255, 95, 109).Sprint,
}

var kindIcon = map[string]string{
	"sub":      "+",
	"port":     "»",
	"live":     "●",
	"vhost":    "◈",
	"axfr":     "⚡",
	"takeover": "⚠",
}

// Stats aggregates scan-wide counters (atomically updated by UI loop).
type Stats struct {
	targetsTotal int
	targetsDone  int
	subs         int
	ports        int
	live         int
	takeovers    int
	phase        string // last active phase
	frame        int
	start        time.Time
}

// UI is the single-goroutine stdout renderer driven by engine events.
type UI struct {
	events  chan scanner.Event
	done    chan struct{}
	tty     bool
	stats   Stats
	lastLen int // visible width of last stats line (for clearing)
}

// NewUI creates the renderer. Call Run in a goroutine, then Close when done.
func NewUI(targetsTotal int) *UI {
	return &UI{
		events: make(chan scanner.Event, 4096),
		done:   make(chan struct{}),
		tty:    isTTY(),
		stats:  Stats{targetsTotal: targetsTotal, start: time.Now()},
	}
}

// Emitter adapts the channel to scanner.Emitter.
func (u *UI) Emitter() scanner.Emitter {
	return func(ev scanner.Event) {
		select {
		case u.events <- ev:
		default: // never block the engine on a full UI buffer
		}
	}
}

// Close shuts the renderer down and waits for the final flush.
func (u *UI) Close() {
	close(u.events)
	<-u.done
}

// Run consumes events until Close. One goroutine owns all stdout writes.
func (u *UI) Run() {
	defer close(u.done)
	tick := time.NewTicker(90 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case ev, ok := <-u.events:
			if !ok {
				u.clearStatsLine()
				return
			}
			u.handle(ev)
		case <-tick.C:
			if u.tty {
				u.renderStatsLine()
			}
		}
	}
}

func (u *UI) handle(ev scanner.Event) {
	switch ev.Type {
	case scanner.EvPhase:
		u.stats.phase = ev.Message
		u.printLine(ev, fmt.Sprintf("%s %s", dim.Sprint("┌"), pterm.NewRGB(0, 229, 255).Sprint(ev.Message)))
	case scanner.EvFound:
		switch ev.Kind {
		case "sub":
			u.stats.subs++
		case "port":
			u.stats.ports++
		case "live":
			u.stats.live++
		case "takeover":
			u.stats.takeovers++
		}
		icon := kindIcon[ev.Kind]
		if icon == "" {
			icon = "•"
		}
		colored := levelColor[scanner.LevelSuccess](fmt.Sprintf("%s %s", icon, ev.Message))
		switch ev.Kind {
		case "takeover":
			colored = pterm.NewRGB(255, 95, 109).Sprint("⚠ " + ev.Message)
		case "axfr":
			colored = pterm.NewRGB(255, 95, 109).Sprint("⚡ " + ev.Message)
		}
		u.printLine(ev, colored)
	case scanner.EvLog:
		paint := levelColor[ev.Level]
		if paint == nil {
			paint = levelColor[scanner.LevelInfo]
		}
		u.printLine(ev, paint(ev.Message))
	case scanner.EvTargetDone:
		u.stats.targetsDone++
		elapsed := time.Since(u.stats.start).Round(time.Millisecond)
		u.printLine(ev, accent.Sprintf("✔ %s done", ev.Target)+dim.Sprintf("  (%d/%d · %s)",
			u.stats.targetsDone, u.stats.targetsTotal, elapsed))
	}
}

// printLine clears the live stats line, prints the log line above it.
func (u *UI) printLine(ev scanner.Event, body string) {
	if u.tty {
		u.clearStatsLine()
	}
	ts := dim.Sprint(time.Now().Format("15:04:05"))
	target := ""
	if ev.Target != "" && ev.Type != scanner.EvPhase {
		target = dim.Sprintf(" %-22s ", truncate(ev.Target, 22))
	} else {
		target = strings.Repeat(" ", 24)
	}
	fmt.Printf("%s %s %s\n", ts, target, body)
	if u.tty {
		u.renderStatsLine()
	}
}

// renderStatsLine draws the animated single-line dashboard.
func (u *UI) renderStatsLine() {
	s := &u.stats
	frame := spinnerFrames[s.frame%len(spinnerFrames)]
	s.frame++
	elapsed := time.Since(s.start).Round(time.Second)

	// plain is the uncolored twin, measured to know how much to blank out;
	// counting runes of the colored string would include the escape codes.
	plain := fmt.Sprintf("%s %d/%d targets  subs %d  ports %d  live %d  tk %d  %s",
		frame, s.targetsDone, s.targetsTotal, s.subs, s.ports, s.live, s.takeovers, elapsed)
	line := strings.Replace(plain, frame, pterm.NewRGB(213, 0, 249).Sprint(frame), 1)

	u.lastLen = len([]rune(plain))
	fmt.Print("\r" + dim.Sprint(" ") + line)
}

func (u *UI) clearStatsLine() {
	if u.lastLen > 0 {
		fmt.Print("\r" + strings.Repeat(" ", u.lastLen+3) + "\r")
		u.lastLen = 0
	}
}

// ─── Final summaries ──────────────────────────────────────

// PrintTargetPanel renders a boxed per-target summary (single-target mode).
func PrintTargetPanel(r *scanner.Result) {
	var b strings.Builder

	fmt.Fprintf(&b, "%s %s\n", dim.Sprint("ips      "), orDash(strings.Join(r.IPs, ", ")))

	if r.DNS != nil {
		fmt.Fprintf(&b, "%s A:%d AAAA:%d MX:%d NS:%d TXT:%d\n",
			dim.Sprint("dns      "),
			len(r.DNS.A), len(r.DNS.AAAA), len(r.DNS.MX), len(r.DNS.NS), len(r.DNS.TXT))
	}

	fmt.Fprintf(&b, "%s %d   %s %d   %s %d\n",
		dim.Sprint("subs     "), len(r.Subdomains),
		dim.Sprint("ports"), len(r.Ports),
		dim.Sprint("live "), len(r.Web))

	if len(r.Web) > 0 {
		w := r.Web[0]
		fmt.Fprintf(&b, "%s %d %s\n", dim.Sprint("main     "), w.Status, w.Title)
		if len(w.Technologies) > 0 {
			fmt.Fprintf(&b, "%s %s\n", dim.Sprint("tech     "), strings.Join(w.Technologies, ", "))
		}
		if w.WAF != "" {
			fmt.Fprintf(&b, "%s %s\n", dim.Sprint("waf      "),
				pterm.NewRGB(255, 214, 90).Sprint(w.WAF))
		}
	}

	if r.TLS != nil {
		tlsLine := fmt.Sprintf("%s · valid to %s", r.TLS.Version, r.TLS.ValidTo)
		if r.TLS.Expired {
			tlsLine += "  " + pterm.NewRGB(255, 95, 109).Sprint("EXPIRED")
		}
		fmt.Fprintf(&b, "%s %s\n", dim.Sprint("tls      "), tlsLine)
	}

	if len(r.ZoneTransfer) > 0 {
		fmt.Fprintf(&b, "%s %s\n", dim.Sprint("axfr     "),
			pterm.NewRGB(255, 95, 109).Sprintf("ZONE TRANSFER OK — %d records!", len(r.ZoneTransfer[0].Records)))
	}

	if len(r.VHosts) > 0 {
		fmt.Fprintf(&b, "%s %d hidden\n", dim.Sprint("vhosts   "), len(r.VHosts))
		for i, v := range r.VHosts {
			if i >= 5 {
				fmt.Fprintf(&b, "           … and %d more\n", len(r.VHosts)-5)
				break
			}
			fmt.Fprintf(&b, "           %s → %d (%db)\n", v.Host, v.Status, v.Size)
		}
	}

	if len(r.Takeovers) > 0 {
		fmt.Fprintf(&b, "%s %s\n", dim.Sprint("takeover "),
			pterm.NewRGB(255, 95, 109).Sprintf("%d candidates!", len(r.Takeovers)))
		for _, t := range r.Takeovers {
			fmt.Fprintf(&b, "           %s → %s (%s)\n", t.Host, t.CNAME, t.Service)
		}
	}

	if r.Error != "" {
		fmt.Fprintf(&b, "%s %s\n", dim.Sprint("errors   "), r.Error)
	}

	fmt.Fprintf(&b, "%s %d ms", dim.Sprint("duration "), r.DurationMs)

	pterm.Println()
	pterm.DefaultBox.
		WithTitle(" " + r.Target + " ").
		WithTitleTopLeft().
		WithBoxStyle(pterm.NewStyle(pterm.FgLightCyan)).
		Println(strings.TrimRight(b.String(), "\n"))
}

// PrintBatchTable renders the final boxed table for multi-target runs.
func PrintBatchTable(results []*scanner.Result) {
	pterm.Println()
	pterm.DefaultSection.WithLevel(2).Println("scan results")

	data := [][]string{{"target", "subs", "ports", "live", "tech", "waf", "takeover", "time"}}
	for _, r := range results {
		tech := "-"
		waf := "-"
		if len(r.Web) > 0 {
			if len(r.Web[0].Technologies) > 0 {
				tech = truncate(strings.Join(r.Web[0].Technologies, ", "), 28)
			}
			if r.Web[0].WAF != "" {
				waf = r.Web[0].WAF
			}
		}
		tk := "-"
		if len(r.Takeovers) > 0 {
			tk = pterm.NewRGB(255, 95, 109).Sprintf("%d !", len(r.Takeovers))
		}
		data = append(data, []string{
			r.Target,
			fmt.Sprint(len(r.Subdomains)),
			fmt.Sprint(len(r.Ports)),
			fmt.Sprint(len(r.Web)),
			tech, waf, tk,
			fmt.Sprintf("%.1fs", float64(r.DurationMs)/1000),
		})
	}
	_ = pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(data).Render()
}

// PrintSaved lists written output files.
func PrintSaved(files []string) {
	for _, f := range files {
		pterm.Println(accent.Sprint(" ✔ saved ") + dim.Sprint(f))
	}
}

// DisableColors turns off all styling (for -no-color / non-TTY).
func DisableColors() { pterm.DisableStyling() }

// ─── helpers ──────────────────────────────────────────────

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

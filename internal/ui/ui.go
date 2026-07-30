// Package ui renders dscan's terminal interface: gradient banner,
// animated live-stats line, finding feed, and summary panels.
package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pterm/pterm"

	"dscan/internal/scanner"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

var levelStyle = map[scanner.Level]struct {
	label string
	color pterm.RGB
}{
	scanner.LevelInfo:    {"INFO", info},
	scanner.LevelSuccess: {"OK", accent},
	scanner.LevelWarn:    {"WARN", warning},
	scanner.LevelError:   {"ERROR", danger},
}

var findingStyle = map[string]struct {
	label string
	color pterm.RGB
}{
	"sub":      {"SUB", info},
	"port":     {"PORT", phase},
	"live":     {"WEB", accent},
	"vhost":    {"VHOST", phase},
	"axfr":     {"AXFR", danger},
	"takeover": {"RISK", danger},
}

var phaseDescription = map[string]string{
	"dns":      "resolve DNS records and network ownership",
	"sub":      "discover and validate subdomains",
	"ports":    "scan TCP services and collect banners",
	"vhost":    "discover hidden virtual hosts",
	"http":     "probe web services and fingerprints",
	"crawl":    "collect in-scope URLs and endpoints",
	"takeover": "check dangling DNS takeover candidates",
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
	phaseTarget  string
	step         int
	totalSteps   int
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
	tlsSeen map[string]int
}

// NewUI creates the renderer. Call Run in a goroutine, then Close when done.
func NewUI(targetsTotal int) *UI {
	return &UI{
		events:  make(chan scanner.Event, 4096),
		done:    make(chan struct{}),
		tty:     isTTY(),
		stats:   Stats{targetsTotal: targetsTotal, start: time.Now()},
		tlsSeen: make(map[string]int),
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
		label, description := u.describePhase(ev)
		u.stats.phase = label
		u.stats.phaseTarget = ev.Target
		u.stats.step = ev.Step
		u.stats.totalSteps = ev.Total
		step := "STEP"
		if ev.Step > 0 && ev.Total > 0 {
			step = fmt.Sprintf("STEP %02d/%02d", ev.Step, ev.Total)
		}
		u.printLine(ev, badge(step, phase)+" "+info.Sprint(strings.ToUpper(label))+
			dim.Sprint("  ·  "+description))
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
		style, ok := findingStyle[ev.Kind]
		if !ok {
			style = struct {
				label string
				color pterm.RGB
			}{"FOUND", accent}
		}
		u.printLine(ev, badge(style.label, style.color)+" "+style.color.Sprint(ev.Message))
	case scanner.EvLog:
		style, ok := levelStyle[ev.Level]
		if !ok {
			style = levelStyle[scanner.LevelInfo]
		}
		u.printLine(ev, badge(style.label, style.color)+" "+style.color.Sprint(ev.Message))
	case scanner.EvTargetDone:
		u.stats.targetsDone++
		elapsed := time.Since(u.stats.start).Round(time.Millisecond)
		u.printLine(ev, badge("DONE", accent)+accent.Sprint(" target completed")+
			dim.Sprintf("  ·  %d/%d targets  ·  %s", u.stats.targetsDone, u.stats.targetsTotal, elapsed))
	}
}

// printLine clears the live stats line, prints the log line above it.
func (u *UI) printLine(ev scanner.Event, body string) {
	if u.tty {
		u.clearStatsLine()
	}
	ts := dim.Sprint(time.Now().Format("15:04:05"))
	target := dim.Sprintf(" %-24s", truncate(ev.Target, 24))
	fmt.Printf("%s%s %s\n", ts, target, body)
	if u.tty {
		u.renderStatsLine()
	}
}

func (u *UI) describePhase(ev scanner.Event) (string, string) {
	if ev.Message == "tls" {
		u.tlsSeen[ev.Target]++
		if u.tlsSeen[ev.Target] == 1 {
			return "tls seed", "extract certificate names for discovery"
		}
		return "tls endpoints", "validate certificates on live services"
	}
	if description := phaseDescription[ev.Message]; description != "" {
		return ev.Message, description
	}
	return ev.Message, "run scan module"
}

// renderStatsLine draws the animated single-line dashboard.
func (u *UI) renderStatsLine() {
	s := &u.stats
	frame := spinnerFrames[s.frame%len(spinnerFrames)]
	s.frame++
	elapsed := time.Since(s.start).Round(time.Second)

	// plain is the uncolored twin, measured to know how much to blank out;
	// counting runes of the colored string would include the escape codes.
	active := ""
	if s.phase != "" {
		active = fmt.Sprintf("  │  %s %02d/%02d", truncate(s.phaseTarget, 16), s.step, s.totalSteps)
	}
	plain := fmt.Sprintf("%s %d/%d targets  │  sub %d  port %d  web %d  risk %d%s  │  %s",
		frame, s.targetsDone, s.targetsTotal, s.subs, s.ports, s.live, s.takeovers, active, elapsed)
	line := phase.Sprint(frame) +
		dim.Sprintf(" %d/%d targets  │  ", s.targetsDone, s.targetsTotal) +
		info.Sprintf("sub %d", s.subs) + dim.Sprint("  ") +
		phase.Sprintf("port %d", s.ports) + dim.Sprint("  ") +
		accent.Sprintf("web %d", s.live) + dim.Sprint("  ") +
		danger.Sprintf("risk %d", s.takeovers)
	if active != "" {
		line += dim.Sprint("  │  "+truncate(s.phaseTarget, 16)+" ") +
			phase.Sprintf("%02d/%02d", s.step, s.totalSteps)
	}
	line += dim.Sprint("  │  " + elapsed.String())

	u.lastLen = len([]rune(plain))
	fmt.Print("\r " + line)
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

	statusLabel, statusColor := resultStatus(r)
	fmt.Fprintf(&b, "%s %s\n\n", dim.Sprint("status     "), badge(statusLabel, statusColor))
	fmt.Fprintf(&b, "%s %s\n", dim.Sprint("addresses  "), orDash(strings.Join(r.IPs, ", ")))

	if r.DNS != nil {
		fmt.Fprintf(&b, "%s A %d  ·  AAAA %d  ·  MX %d  ·  NS %d  ·  TXT %d\n",
			dim.Sprint("dns        "), len(r.DNS.A), len(r.DNS.AAAA),
			len(r.DNS.MX), len(r.DNS.NS), len(r.DNS.TXT))
	}

	fmt.Fprintf(&b, "%s subdomains %d  ·  ports %d  ·  web %d  ·  vhosts %d  ·  endpoints %d\n",
		dim.Sprint("assets     "), len(r.Subdomains), len(r.Ports), len(r.Web),
		len(r.VHosts), len(r.Endpoints))

	if len(r.Web) > 0 {
		w := r.Web[0]
		fmt.Fprintf(&b, "%s %s  %s\n", dim.Sprint("primary    "), colorHTTPStatus(w.Status), orDash(w.Title))
		fmt.Fprintf(&b, "%s %s", strings.Repeat(" ", 11), w.URL)
		if w.ResponseMs > 0 {
			b.WriteString(dim.Sprintf("  ·  %dms", w.ResponseMs))
		}
		b.WriteByte('\n')
		if len(w.Technologies) > 0 {
			fmt.Fprintf(&b, "%s %s\n", dim.Sprint("technology "), strings.Join(w.Technologies, ", "))
		}
		if w.WAF != "" {
			fmt.Fprintf(&b, "%s %s\n", dim.Sprint("waf        "), warning.Sprint(w.WAF))
		}
	}

	if r.TLS != nil {
		tlsLine := fmt.Sprintf("%s · valid to %s", r.TLS.Version, r.TLS.ValidTo)
		if r.TLS.Expired {
			tlsLine += "  " + badge("EXPIRED", danger)
		} else if r.TLS.Mismatch {
			tlsLine += "  " + badge("MISMATCH", danger)
		} else if r.TLS.DaysLeft > 0 && r.TLS.DaysLeft <= 30 {
			tlsLine += "  " + badge(fmt.Sprintf("%d DAYS", r.TLS.DaysLeft), warning)
		} else {
			tlsLine += "  " + badge("VALID", accent)
		}
		fmt.Fprintf(&b, "%s %s\n", dim.Sprint("tls        "), tlsLine)
	}

	if len(r.ZoneTransfer) > 0 {
		fmt.Fprintf(&b, "%s %s\n", dim.Sprint("axfr       "),
			danger.Sprintf("EXPOSED · %d records", len(r.ZoneTransfer[0].Records)))
	}

	if len(r.VHosts) > 0 {
		fmt.Fprintf(&b, "%s %d hidden\n", dim.Sprint("vhosts     "), len(r.VHosts))
		for i, v := range r.VHosts {
			if i >= 5 {
				fmt.Fprintf(&b, "           … %d more\n", len(r.VHosts)-5)
				break
			}
			fmt.Fprintf(&b, "           %s  %s  %db\n", colorHTTPStatus(v.Status), v.Host, v.Size)
		}
	}

	if len(r.Takeovers) > 0 {
		fmt.Fprintf(&b, "%s %s\n", dim.Sprint("takeover   "),
			danger.Sprintf("%d candidate(s)", len(r.Takeovers)))
		for _, t := range r.Takeovers {
			fmt.Fprintf(&b, "           %s → %s (%s)\n", t.Host, t.CNAME, t.Service)
		}
	}

	if failed := failedSources(r); failed > 0 {
		fmt.Fprintf(&b, "%s %s\n", dim.Sprint("sources    "), warning.Sprintf("%d provider(s) unavailable", failed))
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(&b, "%s %s\n", dim.Sprint("errors     "), danger.Sprintf("%d", len(r.Errors)))
		for _, err := range r.Errors {
			fmt.Fprintf(&b, "           %s\n", danger.Sprint("• "+err))
		}
	} else if r.Error != "" {
		fmt.Fprintf(&b, "%s %s\n", dim.Sprint("errors     "), danger.Sprint(r.Error))
	}

	fmt.Fprintf(&b, "%s %.2fs", dim.Sprint("duration   "), float64(r.DurationMs)/1000)

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

	data := [][]string{{"target", "status", "subs", "ports", "web", "endpoints", "signals", "time"}}
	for _, r := range results {
		statusLabel, statusColor := resultStatus(r)
		data = append(data, []string{
			r.Target,
			statusColor.Sprint(statusLabel),
			fmt.Sprint(len(r.Subdomains)),
			fmt.Sprint(len(r.Ports)),
			fmt.Sprint(len(r.Web)),
			fmt.Sprint(len(r.Endpoints)),
			resultSignals(r),
			fmt.Sprintf("%.1fs", float64(r.DurationMs)/1000),
		})
	}
	_ = pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(data).Render()
}

// PrintSaved lists written output files.
func PrintSaved(files []string) {
	if len(files) == 0 {
		return
	}
	location := files[0]
	if len(files) > 1 {
		location = filepath.Dir(files[0])
	}
	pterm.Println()
	pterm.Println(" " + badge("SAVED", accent) + accent.Sprintf(" %d artifact(s)", len(files)) +
		dim.Sprint("  ·  "+location))
}

// DisableColors turns off all styling (for -no-color / non-TTY).
func DisableColors() { pterm.DisableStyling() }

// ─── helpers ──────────────────────────────────────────────

func badge(label string, color pterm.RGB) string {
	return color.Sprint("[" + label + "]")
}

func colorHTTPStatus(code int) string {
	text := fmt.Sprint(code)
	if code == 0 {
		text = "-"
	}
	style := levelStyle[httpStatusLevel(code)]
	return style.color.Sprint(text)
}

func httpStatusLevel(code int) scanner.Level {
	switch {
	case code >= 200 && code < 300:
		return scanner.LevelSuccess
	case code >= 300 && code < 400:
		return scanner.LevelInfo
	case code >= 400 && code < 500:
		return scanner.LevelWarn
	case code >= 500:
		return scanner.LevelError
	default:
		return scanner.LevelInfo
	}
}

func resultStatus(r *scanner.Result) (string, pterm.RGB) {
	if r.Error != "" || len(r.Errors) > 0 {
		return "ERROR", danger
	}
	if len(r.Takeovers) > 0 || len(r.ZoneTransfer) > 0 ||
		r.TLS != nil && (r.TLS.Expired || r.TLS.Mismatch) {
		return "RISK", danger
	}
	if failedSources(r) > 0 {
		return "PARTIAL", warning
	}
	return "OK", accent
}

func failedSources(r *scanner.Result) int {
	failed := 0
	for _, source := range r.Sources {
		if source.Error != "" {
			failed++
		}
	}
	return failed
}

func resultSignals(r *scanner.Result) string {
	var signals []string
	if len(r.Takeovers) > 0 {
		signals = append(signals, danger.Sprintf("%d takeover", len(r.Takeovers)))
	}
	if len(r.ZoneTransfer) > 0 {
		signals = append(signals, danger.Sprint("AXFR"))
	}
	if r.TLS != nil && (r.TLS.Expired || r.TLS.Mismatch) {
		signals = append(signals, danger.Sprint("TLS"))
	}
	if len(r.Web) > 0 && r.Web[0].WAF != "" {
		signals = append(signals, warning.Sprint("WAF "+r.Web[0].WAF))
	}
	if len(signals) == 0 {
		return dim.Sprint("-")
	}
	return truncate(strings.Join(signals, ", "), 30)
}

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

package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pterm/pterm"

	"nexprowl/internal/scanner"
)

func TestHTTPStatusLevel(t *testing.T) {
	tests := map[int]scanner.Level{
		0:   scanner.LevelInfo,
		204: scanner.LevelSuccess,
		302: scanner.LevelInfo,
		404: scanner.LevelWarn,
		503: scanner.LevelError,
	}
	for code, want := range tests {
		if got := httpStatusLevel(code); got != want {
			t.Errorf("status %d: got %s, want %s", code, got, want)
		}
	}
}

func TestResultStatusAndSignals(t *testing.T) {
	tests := []struct {
		result *scanner.Result
		want   string
	}{
		{&scanner.Result{}, "OK"},
		{&scanner.Result{Sources: []scanner.SourceStatus{{Error: "offline"}}}, "PARTIAL"},
		{&scanner.Result{Takeovers: []scanner.TakeoverHit{{Host: "x"}}}, "RISK"},
		{&scanner.Result{TLS: &scanner.TLSResult{Mismatch: true}}, "RISK"},
		{&scanner.Result{Errors: []string{"failed"}}, "ERROR"},
	}
	for _, test := range tests {
		got, _ := resultStatus(test.result)
		if got != test.want {
			t.Errorf("resultStatus(%#v) = %q, want %q", test.result, got, test.want)
		}
	}
	result := &scanner.Result{
		Takeovers:    []scanner.TakeoverHit{{Host: "x"}},
		ZoneTransfer: []scanner.AXFREntry{{Server: "ns"}},
		TLS:          &scanner.TLSResult{Expired: true},
		Web:          []scanner.WebResult{{WAF: "Cloudflare"}},
	}
	for _, want := range []string{"takeover", "AXFR", "TLS", "WAF Cloudflare"} {
		if got := resultSignals(result); !strings.Contains(got, want) {
			t.Errorf("signals %q missing %q", got, want)
		}
	}
	if failedSources(&scanner.Result{Sources: []scanner.SourceStatus{{Error: "x"}, {}}}) != 1 {
		t.Error("failed source count is wrong")
	}
}

func TestRendererAndHumanOutput(t *testing.T) {
	output := captureOutput(t, func() {
		Banner()
		Boot()
		ConfigLine(1, "dns,http", 10, 2, 3, 5, 0)
		PrintHelp()

		renderer := NewUI(1)
		go renderer.Run()
		emit := renderer.Emitter()
		emit(scanner.Event{Type: scanner.EvPhase, Target: "example.com", Message: "tls", Step: 1, Total: 2})
		emit(scanner.Event{Type: scanner.EvFound, Target: "example.com", Kind: "sub", Message: "api.example.com"})
		emit(scanner.Event{Type: scanner.EvFound, Target: "example.com", Kind: "port", Message: "443/tcp"})
		emit(scanner.Event{Type: scanner.EvFound, Target: "example.com", Kind: "live", Message: "https://example.com"})
		emit(scanner.Event{Type: scanner.EvFound, Target: "example.com", Kind: "takeover", Message: "old.example.com"})
		emit(scanner.Event{Type: scanner.EvLog, Target: "example.com", Level: scanner.LevelWarn, Message: "warning"})
		emit(scanner.Event{Type: scanner.EvTargetDone, Target: "example.com"})
		renderer.Close()
		if renderer.stats.targetsDone != 1 || renderer.stats.subs != 1 ||
			renderer.stats.ports != 1 || renderer.stats.live != 1 || renderer.stats.takeovers != 1 {
			t.Fatalf("renderer stats = %#v", renderer.stats)
		}

		result := &scanner.Result{
			Target: "example.com", IPs: []string{"192.0.2.1"},
			Web: []scanner.WebResult{{URL: "https://example.com", Status: 200, Title: "Example"}},
			TLS: &scanner.TLSResult{Version: "TLS 1.3", ValidTo: "2030-01-01"},
		}
		PrintTargetPanel(result)
		PrintBatchTable([]*scanner.Result{result, {Target: "other.test", Error: "failed"}})
		PrintSaved([]string{filepath.Join("results", "run", "report.html")})
	})
	for _, want := range []string{
		"◉", "NEXPROWL", "[READY]", "[RUN]", "nexprowl [flags]",
		"[STEP 01/02]", "[SUB]", "[PORT]", "[WEB]", "[RISK]", "[WARN]", "[DONE]",
		"example.com", "[SAVED]",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("UI output missing %q", want)
		}
	}
}

func TestUIHelpers(t *testing.T) {
	renderer := &UI{tlsSeen: make(map[string]int)}
	first, _ := renderer.describePhase(scanner.Event{Target: "example.com", Message: "tls"})
	second, _ := renderer.describePhase(scanner.Event{Target: "example.com", Message: "tls"})
	if first != "tls seed" || second != "tls endpoints" {
		t.Fatalf("TLS phases = %q, %q", first, second)
	}
	if got := truncate("abcdefgh", 5); got != "abcd…" {
		t.Errorf("truncate = %q", got)
	}
	if orDash("") != "-" || orDash("x") != "x" || gradientString("") != "" {
		t.Error("UI helper output is inconsistent")
	}
	if icon := scanIcon(); !strings.Contains(icon, "◉") || strings.Count(icon, "\n") != 6 {
		t.Errorf("scan icon = %q", icon)
	}
	output := captureOutput(t, func() {
		DisableColors()
		renderer := &UI{
			tty: true,
			stats: Stats{
				targetsTotal: 2, targetsDone: 1, subs: 3, ports: 2, live: 1,
				phase: "http", phaseTarget: "example.com", step: 4, totalSteps: 8,
				start: time.Now().Add(-time.Second),
			},
		}
		renderer.renderStatsLine()
		renderer.clearStatsLine()
	})
	if !strings.Contains(output, "1/2 targets") || !strings.Contains(output, "04/08") {
		t.Errorf("stats output = %q", output)
	}
}

func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	path := filepath.Join(t.TempDir(), "stdout.txt")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = file
	pterm.SetDefaultOutput(file)
	pterm.DisableStyling()
	defer func() {
		os.Stdout = old
		pterm.SetDefaultOutput(old)
		pterm.EnableStyling()
	}()

	fn()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

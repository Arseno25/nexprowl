package ui

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"

	"nexprowl/internal/detect"
	"nexprowl/internal/scanner"
)

var (
	gradStart = pterm.NewRGB(0, 229, 255)   // cyan
	gradEnd   = pterm.NewRGB(213, 0, 249)   // magenta
	accent    = pterm.NewRGB(105, 240, 174) // mint
	dim       = pterm.NewRGB(130, 130, 150) // dim gray
	info      = pterm.NewRGB(87, 199, 255)  // blue
	warning   = pterm.NewRGB(255, 195, 77)  // amber
	danger    = pterm.NewRGB(255, 95, 109)  // red
	phase     = pterm.NewRGB(189, 147, 249) // purple
)

// gradientString fades text from gradStart to gradEnd, rune by rune.
func gradientString(s string) string {
	runes := []rune(s)
	n := float32(len(runes))
	if n == 0 {
		return ""
	}
	var b strings.Builder
	for i, r := range runes {
		b.WriteString(gradStart.Fade(0, n, float32(i), gradEnd).Sprint(string(r)))
	}
	return b.String()
}

// Banner renders the gradient ASCII banner + metadata line.
func Banner() {
	word := "NEXPROWL"
	letters := make([]pterm.Letters, 0, len(word))
	n := float32(len(word))
	for i, ch := range word {
		rgb := gradStart.Fade(0, n, float32(i), gradEnd)
		letters = append(letters, putils.LettersFromStringWithRGB(string(ch), rgb))
	}
	big, _ := pterm.DefaultBigText.WithLetters(letters...).Srender()
	pterm.DefaultCenter.Println(big)

	pterm.DefaultCenter.Println(gradientString("a l l - i n - o n e   d o m a i n   r e c o n n a i s s a n c e"))
	pterm.Println()

	tech, waf, takeover := detect.SignatureCounts()
	meta := fmt.Sprintf("v%s by shadow0x0  ·  %s/%s  ·  %d tech sigs  ·  %d waf sigs  ·  %d takeover fingerprints",
		scanner.Version, runtime.GOOS, runtime.GOARCH, tech, waf, takeover)
	pterm.DefaultCenter.Println(dim.Sprint(meta))
	pterm.DefaultCenter.Println(dim.Sprint(strings.Repeat("─", 64)))
}

// Boot confirms readiness without adding artificial startup delay.
func Boot() {
	pterm.Println(" " + badge("READY", accent) + dim.Sprint(" engine initialized"))
}

// ConfigLine prints the run configuration as a compact, scannable line.
func ConfigLine(targets int, modules string, workers, concurrency, timeoutSec, rate, resolvers int) {
	rateStr := "∞"
	if rate > 0 {
		rateStr = fmt.Sprintf("%d/s", rate)
	}
	resStr := "system"
	if resolvers > 0 {
		resStr = fmt.Sprintf("%d custom", resolvers)
	}
	line := fmt.Sprintf("targets %d  │  modules %s  │  workers %d  │  concurrent %d  │  timeout %ds  │  rate %s  │  dns %s",
		targets, modules, workers, concurrency, timeoutSec, rateStr, resStr)
	pterm.Println(" " + badge("RUN", info) + " " + dim.Sprint(line))
	pterm.Println()
}

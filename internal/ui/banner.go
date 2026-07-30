package ui

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"

	"dscan/internal/detect"
	"dscan/internal/scanner"
)

var (
	gradStart = pterm.NewRGB(0, 229, 255)   // cyan
	gradEnd   = pterm.NewRGB(213, 0, 249)   // magenta
	accent    = pterm.NewRGB(105, 240, 174) // mint
	dim       = pterm.NewRGB(130, 130, 150) // dim gray
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
	word := "DSCAN"
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

// Boot plays the startup animation: a spinner stepping through init stages.
func Boot() {
	steps := []string{
		"loading detection signatures",
		"initializing worker engine",
		"priming dns resolvers",
		"engine ready",
	}
	sp, _ := pterm.DefaultSpinner.
		WithRemoveWhenDone(true).
		WithDelay(110 * time.Millisecond).
		Start(steps[0] + dim.Sprint(" …"))
	for _, s := range steps[1:] {
		time.Sleep(140 * time.Millisecond)
		sp.UpdateText(s + dim.Sprint(" …"))
	}
	time.Sleep(120 * time.Millisecond)
	sp.Success(accent.Sprint("engine ready"))
	// let pterm's spinner goroutine flush its final frame before the
	// event renderer takes over stdout
	time.Sleep(150 * time.Millisecond)
}

// ConfigLine prints the run configuration as a compact gradient line.
func ConfigLine(targets int, modules string, workers, concurrency, timeoutSec, rate, resolvers int) {
	rateStr := "∞"
	if rate > 0 {
		rateStr = fmt.Sprintf("%d/s", rate)
	}
	resStr := "system"
	if resolvers > 0 {
		resStr = fmt.Sprintf("%d custom", resolvers)
	}
	line := fmt.Sprintf(" targets %d · modules %s · workers %d · concurrency %d · timeout %ds · rate %s · dns %s",
		targets, modules, workers, concurrency, timeoutSec, rateStr, resStr)
	pterm.Println(dim.Sprint(" ┌ ") + gradientString(line))
	pterm.Println()
}

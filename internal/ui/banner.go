package ui

import (
	"fmt"
	"strings"

	"github.com/pterm/pterm"
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

func scanLogo() string {
	return strings.Join([]string{
		` _   _           ____                    _ `,
		`| \ | | _____  _|  _ \ _ __ _____      _| |`,
		`|  \| |/ _ \ \/ / |_) | '__/ _ \ \ /\ / / |`,
		`| |\  |  __/>  <|  __/| | | (_) \ V  V /| |`,
		`|_| \_|\___/_/\_\_|   |_|  \___/ \_/\_/ |_|`,
		``,
	}, "\n")
}

// Banner prints the figlet banner + tagline + modules.
func Banner() {
	pterm.DefaultCenter.Println(gradientString(scanLogo()))

	line := accent.Sprint(">_") + "  " +
		gradientString("ALL-IN-ONE DOMAIN RECONNAISSANCE")
	pterm.DefaultCenter.Println(line)

	pterm.DefaultCenter.Println(
		dim.Sprint("dns·axfr·sub·ports·http·vhost·tls·takeover"))
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

package ui

import (
	"fmt"

	"github.com/pterm/pterm"

	"dscan/internal/scanner"
)

// PrintHelp renders the full structured help screen.
func PrintHelp() {
	pterm.Println()
	pterm.DefaultCenter.Println(
		gradientString("d s c a n") +
			dim.Sprintf("  v%s — all-in-one domain reconnaissance", scanner.Version))
	pterm.DefaultCenter.Println(dim.Sprint("by shadow0x0"))
	pterm.Println()

	section("USAGE")
	row(gradientString("dscan [flags] <target.com>"), "")
	row(gradientString("dscan -l targets.txt [flags]"), "")

	section("TARGETS")
	row("-l FILE", "file with target list (one per line, # = comment)")

	section("MODULES  (-m, default: all)")
	row("dns", "A/AAAA/MX/NS/TXT/CNAME · wildcard detect · AXFR zone transfer")
	row("sub", "passive enum (5 sources) + bruteforce + wildcard filtering")
	row("ports", "TCP connect scan · service naming · banner grabbing")
	row("http", "web probe + tech detect (70 sigs) + WAF detect (passive & active)")
	row("vhost", "hidden virtual host discovery (Host-header & SNI fuzzing)")
	row("tls", "certificate info · expiry check · SANs extraction")
	row("takeover", "dangling CNAME → claimable service detection (50 services)")

	section("SCAN TUNING")
	row("-p SPEC", "ports: top100 (default) | full | 80,443 | 1-1024")
	row("-w FILE", "custom subdomain wordlist")
	row("-passive", "skip bruteforce (passive sources only)")
	row("-probe-subs", "HTTP-probe discovered subdomains (default true)")

	section("PERFORMANCE & STEALTH")
	row("-t N", "workers per module (default 300)")
	row("-T N", "concurrent targets in batch mode (default 5)")
	row("-timeout N", "network timeout in seconds (default 4)")
	row("-r FILE", "custom DNS resolvers, round-robin (default: system)")
	row("-rate N", "max network ops/sec per target (default: unlimited)")

	section("OUTPUT")
	row("-o PATH", "file (.json/.jsonl/.csv/.md/.txt) or directory")
	row("-format FMT", "override format: json | jsonl | csv | md | txt")
	row("-silent", "no UI — one summary line per target (script-friendly)")
	row("-no-color", "disable colored output")

	section("MISC")
	row("-h, --help", "show this help")
	row("-version", "print version and exit")

	section("EXAMPLES")
	examples([][2]string{
		{"dscan example.com", "full scan, single target"},
		{"dscan -l targets.txt -T 10 -o results/", "batch 10 concurrent → per-target files + summary.csv"},
		{"dscan example.com -m sub,http -t 500", "subdomains + http only, 500 workers"},
		{"dscan example.com -p 1-10000 -t 1000", "wide port scan"},
		{"dscan example.com -m dns", "dns records + zone transfer attempt"},
		{"dscan example.com -m dns,vhost", "hunt hidden virtual hosts"},
		{"dscan example.com -r resolvers.txt -rate 50", "stealth: custom resolvers + rate limit"},
		{"dscan -l targets.txt -passive -silent -o subs.jsonl", "passive, pipe-ready for jq/nuclei"},
		{"dscan -l targets.txt -o report.md", "markdown report for bug bounty notes"},
	})
	pterm.Println()
}

func section(title string) {
	pterm.Println()
	pterm.Println(pterm.NewRGB(0, 229, 255).Sprint("  "+title))
}

func row(flag, desc string) {
	if desc == "" {
		fmt.Printf("  %s\n", flag)
		return
	}
	fmt.Printf("  %s %s\n", accent.Sprintf("%-14s", flag), dim.Sprint(desc))
}

func examples(items [][2]string) {
	for _, ex := range items {
		cmd := gradientString(ex[0])
		pad := 52 - len(ex[0])
		if pad < 2 {
			pad = 2
		}
		fmt.Printf("  %s %s%s%s\n", accent.Sprint("›"), cmd, fmt.Sprintf("%*s", pad, ""), dim.Sprint(ex[1]))
	}
}

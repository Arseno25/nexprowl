package ui

import (
	"fmt"

	"github.com/pterm/pterm"

	"nexprowl/internal/scanner"
)

// PrintHelp renders the full structured help screen.
func PrintHelp() {
	pterm.Println()
	pterm.DefaultCenter.Println(
		gradientString("N e x P r o w l") +
			dim.Sprintf("  v%s — all-in-one domain reconnaissance", scanner.Version))
	pterm.DefaultCenter.Println(dim.Sprint("by shadow0x0"))
	pterm.Println()

	section("USAGE")
	row(gradientString("nexprowl [flags] <target.com>"), "")
	row(gradientString("nexprowl -l targets.txt [flags]"), "")

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
	row("crawl", "bounded in-scope HTML/JS/robots/sitemap endpoint discovery")

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
	row("-scan-all-ips", "port-scan every resolved IPv4/IPv6 address")
	row("-ports-subs", "port-scan discovered subdomains")
	row("-probe-both", "probe both HTTP and HTTPS on web ports")
	row("-active", "enable intrusive checks such as active WAF probing")

	section("SCOPE & DISCOVERY")
	row("-include DOMAINS", "extra in-scope domains, comma-separated")
	row("-exclude DOMAINS", "out-of-scope domains, comma-separated")
	row("-max-hosts N", "maximum discovered hosts per target (default 10000)")
	row("-crawl-depth N", "maximum crawler depth (default 2)")
	row("-crawl-max N", "maximum crawled URLs per target (default 500)")

	section("OUTPUT")
	row("-o PATH", "output file or directory (default: results/)")
	row("-format FMT", "override format: json | jsonl | csv | md | html | txt")
	row("-emit FIELD", "stdout: subdomains | urls | hostports | ips | endpoints | jsonl")
	row("-screenshot", "capture live pages with installed Chrome/Chromium")
	row("-chrome PATH", "custom Chrome/Chromium executable")
	row("-webhook URL", "POST scan summary to a webhook")
	row("-silent", "no UI — one summary line per target (script-friendly)")
	row("-no-color", "disable colored output")

	section("MISC")
	row("-h, --help", "show this help")
	row("-version", "print version and exit")

	section("EXAMPLES")
	examples([][2]string{
		{"nexprowl example.com", "full scan, single target"},
		{"nexprowl -l targets.txt -T 10", "batch 10 concurrent → results/"},
		{"nexprowl example.com -m sub,http -t 500", "subdomains + http only, 500 workers"},
		{"nexprowl example.com -p 1-10000 -t 1000", "wide port scan"},
		{"nexprowl example.com -m dns", "dns records + zone transfer attempt"},
		{"nexprowl example.com -m dns,vhost", "hunt hidden virtual hosts"},
		{"nexprowl example.com -r resolvers.txt -rate 50", "stealth: custom resolvers + rate limit"},
		{"nexprowl -l targets.txt -passive -silent -o results/subs.jsonl", "passive, pipe-ready for jq/nuclei"},
		{"nexprowl -l targets.txt -o results/report.md", "markdown report for bug bounty notes"},
		{"nexprowl example.com -o results/report.html", "standalone HTML report"},
		{"cat domains.txt | nexprowl -silent -emit urls", "pipeline input and URL output"},
		{"nexprowl diff results/old results/new", "compare two scan runs"},
	})
	pterm.Println()
}

func section(title string) {
	pterm.Println()
	pterm.Println(pterm.NewRGB(0, 229, 255).Sprint("  " + title))
}

func row(flag, desc string) {
	if desc == "" {
		fmt.Printf("  %s\n", flag)
		return
	}
	fmt.Printf("  %s %s\n", accent.Sprintf("%-20s", flag), dim.Sprint(desc))
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

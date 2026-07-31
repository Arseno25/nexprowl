// Package config parses and validates command-line configuration.
package config

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"nexprowl/internal/data"
	"nexprowl/internal/scanner"
)

// Config is the fully-resolved runtime configuration.
type Config struct {
	Targets  []string
	Opts     *scanner.Options
	Output   string // -o path (file or directory)
	Format   string // explicit format override
	Emit     string
	Webhook  string
	Silent   bool
	NoColor  bool
	ShowVer  bool
	ShowHelp bool
	Modules  string // raw module list for display
	TimeoutS int
}

// valueFlags are flags that consume the next argument.
var valueFlags = map[string]bool{
	"l": true, "m": true, "p": true, "t": true, "T": true,
	"timeout": true, "w": true, "o": true, "format": true,
	"r": true, "rate": true, "include": true, "exclude": true,
	"max-hosts": true, "crawl-depth": true, "crawl-max": true,
	"chrome": true, "emit": true, "webhook": true,
}

// reorderArgs moves flags before positionals so both
// "nexprowl -t 200 example.com" and "nexprowl example.com -t 200" work.
func reorderArgs(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if strings.Contains(name, "=") {
				continue
			}
			if valueFlags[name] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			positional = append(positional, a)
		}
	}
	return append(flags, positional...)
}

// Load parses os.Args into a validated Config.
func Load() (*Config, error) {
	os.Args = append(os.Args[:1], reorderArgs(os.Args[1:])...)

	var (
		listFile    = flag.String("l", "", "file with target list (one per line)")
		modules     = flag.String("m", "dns,sub,ports,http,vhost,tls,takeover,crawl", "modules to run")
		portsSpec   = flag.String("p", "top100", "ports: top100 | full | 80,443 | 1-1024")
		workers     = flag.Int("t", 300, "workers per module")
		concurrency = flag.Int("T", 5, "concurrent targets (batch mode)")
		timeout     = flag.Int("timeout", 4, "network timeout in seconds")
		wordlist    = flag.String("w", "", "custom subdomain wordlist file")
		resolvers   = flag.String("r", "", "file with DNS resolvers (one per line, default: system)")
		rate        = flag.Int("rate", 0, "max network ops/sec per target (0 = unlimited)")
		include     = flag.String("include", "", "extra in-scope domains (comma-separated)")
		exclude     = flag.String("exclude", "", "out-of-scope domains (comma-separated)")
		maxHosts    = flag.Int("max-hosts", 10000, "maximum discovered hosts per target")
		scanAllIPs  = flag.Bool("scan-all-ips", false, "scan every resolved IPv4/IPv6 address")
		portsSubs   = flag.Bool("ports-subs", false, "port-scan discovered subdomains")
		probeBoth   = flag.Bool("probe-both", false, "probe both HTTP and HTTPS")
		active      = flag.Bool("active", false, "enable intrusive active checks")
		crawlDepth  = flag.Int("crawl-depth", 2, "maximum crawler depth")
		crawlMax    = flag.Int("crawl-max", 500, "maximum crawled URLs per target")
		screenshot  = flag.Bool("screenshot", false, "capture live pages with system Chrome")
		chrome      = flag.String("chrome", "", "path to Chrome/Chromium executable")
		passive     = flag.Bool("passive", false, "passive subdomains only (skip bruteforce)")
		probeSubs   = flag.Bool("probe-subs", true, "HTTP-probe discovered subdomains")
		stealth     = flag.Bool("stealth", false, "low-noise mode (rate=10, workers=10, timeout=8, passive)")
		output      = flag.String("o", "results", "output path: file (.json/.jsonl/.csv/.md/.html/.txt) or directory")
		format      = flag.String("format", "", "output format override: json|jsonl|csv|md|html|txt")
		emit        = flag.String("emit", "", "stdout findings: subdomains|urls|hostports|ips|endpoints|jsonl")
		webhook     = flag.String("webhook", "", "webhook URL for scan/diff notification")
		silent      = flag.Bool("silent", false, "no UI; one summary line per target")
		noColor     = flag.Bool("no-color", false, "disable colors")
		showVer     = flag.Bool("version", false, "print version and exit")
	)
	var help bool
	flag.BoolVar(&help, "h", false, "show help")
	flag.BoolVar(&help, "help", false, "show help")
	flag.Usage = usage
	flag.Parse()

	// A zero/negative pool size starves every module worker loop and hangs
	// the scan on an unbuffered job channel, so clamp before anything uses it.
	*workers = atLeast(*workers, 1)
	*concurrency = atLeast(*concurrency, 1)
	*timeout = atLeast(*timeout, 1)

	cfg := &Config{
		Output:   *output,
		Format:   *format,
		Emit:     strings.ToLower(strings.TrimSpace(*emit)),
		Webhook:  strings.TrimSpace(*webhook),
		Silent:   *silent,
		NoColor:  *noColor,
		ShowVer:  *showVer,
		ShowHelp: help,
		Modules:  *modules,
		TimeoutS: *timeout,
	}
	if cfg.Emit != "" {
		cfg.Silent = true
	}
	if *showVer || help {
		return cfg, nil
	}

	// targets
	if *listFile != "" {
		t, err := LoadLines(*listFile)
		if err != nil {
			return nil, fmt.Errorf("target list: %w", err)
		}
		cfg.Targets = append(cfg.Targets, t...)
	}
	cfg.Targets = append(cfg.Targets, flag.Args()...)
	if len(cfg.Targets) == 0 {
		if stat, err := os.Stdin.Stat(); err == nil && stat.Mode()&os.ModeCharDevice == 0 {
			t, err := LoadReader(os.Stdin)
			if err != nil {
				return nil, fmt.Errorf("stdin: %w", err)
			}
			cfg.Targets = append(cfg.Targets, t...)
		}
	}
	if len(cfg.Targets) == 0 {
		usage()
		return nil, fmt.Errorf("no targets given")
	}

	// modules
	validModules := map[string]bool{
		"dns": true, "sub": true, "ports": true, "http": true,
		"vhost": true, "tls": true, "takeover": true, "crawl": true,
	}
	mods := map[string]bool{}
	for _, m := range strings.Split(*modules, ",") {
		if m = strings.TrimSpace(strings.ToLower(m)); m != "" {
			if !validModules[m] {
				return nil, fmt.Errorf("unknown module %q", m)
			}
			mods[m] = true
		}
	}

	if *format != "" {
		switch strings.ToLower(*format) {
		case "json", "jsonl", "csv", "md", "html", "txt":
		default:
			return nil, fmt.Errorf("unknown output format %q", *format)
		}
	}
	if cfg.Emit != "" {
		switch cfg.Emit {
		case "subdomains", "urls", "hostports", "ips", "endpoints", "jsonl":
		default:
			return nil, fmt.Errorf("unknown emit field %q", cfg.Emit)
		}
	}

	normalizeDomains := func(spec string) ([]string, error) {
		var out []string
		for _, raw := range strings.Split(spec, ",") {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			host, err := scanner.NormalizeTarget(raw)
			if err != nil {
				return nil, err
			}
			out = append(out, host)
		}
		return scanner.UniqueSorted(out), nil
	}
	includeDomains, err := normalizeDomains(*include)
	if err != nil {
		return nil, fmt.Errorf("include: %w", err)
	}
	excludeDomains, err := normalizeDomains(*exclude)
	if err != nil {
		return nil, fmt.Errorf("exclude: %w", err)
	}

	seenTargets := map[string]bool{}
	normalizedTargets := make([]string, 0, len(cfg.Targets))
	for _, raw := range cfg.Targets {
		target, err := scanner.NormalizeTarget(raw)
		if err != nil {
			return nil, err
		}
		if !seenTargets[target] {
			seenTargets[target] = true
			normalizedTargets = append(normalizedTargets, target)
		}
	}
	cfg.Targets = normalizedTargets

	// ports
	ports, err := data.ParsePorts(*portsSpec)
	if err != nil {
		return nil, fmt.Errorf("ports: %w", err)
	}

	// wordlist
	wl := data.Subdomains()
	if *wordlist != "" {
		wl, err = LoadLines(*wordlist)
		if err != nil {
			return nil, fmt.Errorf("wordlist: %w", err)
		}
	}

	// custom resolvers
	var resolverList []string
	if *resolvers != "" {
		lines, err := LoadLines(*resolvers)
		if err != nil {
			return nil, fmt.Errorf("resolvers: %w", err)
		}
		resolverList = normalizeResolvers(lines)
		if len(resolverList) == 0 {
			return nil, fmt.Errorf("resolvers: no valid servers in %s", *resolvers)
		}
	}

	cfg.Opts = &scanner.Options{
		Modules:     mods,
		Workers:     *workers,
		Concurrency: *concurrency,
		Timeout:     time.Duration(*timeout) * time.Second,
		Ports:       ports,
		Wordlist:    wl,
		PassiveOnly: *passive,
		ProbeSubs:   *probeSubs,
		Resolvers:   resolverList,
		Rate:        *rate,
		Include:     includeDomains,
		Exclude:     excludeDomains,
		MaxHosts:    atLeast(*maxHosts, 1),
		ScanAllIPs:  *scanAllIPs,
		PortsSubs:   *portsSubs,
		ProbeBoth:   *probeBoth,
		Active:      *active,
		Stealth:     *stealth,
		CrawlDepth:  atLeast(*crawlDepth, 0),
		CrawlMax:    atLeast(*crawlMax, 1),
		Screenshot:  *screenshot,
		ChromePath:  strings.TrimSpace(*chrome),
	}
	if *stealth {
		cfg.Opts.Workers = 10
		cfg.Opts.Rate = 10
		cfg.Opts.Timeout = 8 * time.Second
		cfg.TimeoutS = 8
		cfg.Opts.PassiveOnly = true
	}
	return cfg, nil
}

func atLeast(v, floor int) int {
	if v < floor {
		return floor
	}
	return v
}

// normalizeResolvers ensures every server is in host:port form.
func normalizeResolvers(lines []string) []string {
	var out []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(l); err != nil {
			l = net.JoinHostPort(l, "53")
		}
		out = append(out, l)
	}
	return out
}

// LoadLines reads a trimmed, comment-stripped, deduped line list.
func LoadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return LoadReader(f)
}

// LoadReader reads the same line format as LoadLines from stdin or a file.
func LoadReader(r io.Reader) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; !ok {
			seen[line] = struct{}{}
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

func usage() {
	fmt.Fprintf(os.Stderr, `
  NexProwl — all-in-one domain reconnaissance (by shadow0x0)

  Usage:
    nexprowl [flags] example.com
    nexprowl -l targets.txt -T 10

  Run 'nexprowl --help' for the full flag reference and examples.
`)
}

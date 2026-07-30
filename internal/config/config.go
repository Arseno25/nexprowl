// Package config parses and validates command-line configuration.
package config

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"dscan/internal/data"
	"dscan/internal/scanner"
)

// Config is the fully-resolved runtime configuration.
type Config struct {
	Targets  []string
	Opts     *scanner.Options
	Output   string // -o path (file or directory)
	Format   string // explicit format override
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
	"r": true, "rate": true,
}

// reorderArgs moves flags before positionals so both
// "dscan -t 200 example.com" and "dscan example.com -t 200" work.
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
		modules     = flag.String("m", "dns,sub,ports,http,vhost,tls,takeover", "modules to run")
		portsSpec   = flag.String("p", "top100", "ports: top100 | full | 80,443 | 1-1024")
		workers     = flag.Int("t", 300, "workers per module")
		concurrency = flag.Int("T", 5, "concurrent targets (batch mode)")
		timeout     = flag.Int("timeout", 4, "network timeout in seconds")
		wordlist    = flag.String("w", "", "custom subdomain wordlist file")
		resolvers   = flag.String("r", "", "file with DNS resolvers (one per line, default: system)")
		rate        = flag.Int("rate", 0, "max network ops/sec per target (0 = unlimited)")
		passive     = flag.Bool("passive", false, "passive subdomains only (skip bruteforce)")
		probeSubs   = flag.Bool("probe-subs", true, "HTTP-probe discovered subdomains")
		output      = flag.String("o", "results", "output path: file (.json/.jsonl/.csv/.md/.html/.txt) or directory")
		format      = flag.String("format", "", "output format override: json|jsonl|csv|md|html|txt")
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
		Silent:   *silent,
		NoColor:  *noColor,
		ShowVer:  *showVer,
		ShowHelp: help,
		Modules:  *modules,
		TimeoutS: *timeout,
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
		usage()
		return nil, fmt.Errorf("no targets given")
	}

	// modules
	mods := map[string]bool{}
	for _, m := range strings.Split(*modules, ",") {
		if m = strings.TrimSpace(strings.ToLower(m)); m != "" {
			mods[m] = true
		}
	}

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

	seen := map[string]struct{}{}
	var out []string
	sc := bufio.NewScanner(f)
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
  dscan — all-in-one domain reconnaissance (by shadow0x0)

  Usage:
    dscan [flags] example.com
    dscan -l targets.txt -T 10

  Run 'dscan --help' for the full flag reference and examples.
`)
}

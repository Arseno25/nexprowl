package config

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReorderArgs(t *testing.T) {
	cases := []struct {
		in, want []string
	}{
		// positionals moved behind flags, both orders equivalent
		{[]string{"-t", "200", "example.com"}, []string{"-t", "200", "example.com"}},
		{[]string{"example.com", "-t", "200"}, []string{"-t", "200", "example.com"}},
		// bool flags must not swallow the following positional
		{[]string{"example.com", "-silent"}, []string{"-silent", "example.com"}},
		{[]string{"-passive", "a.com", "b.com"}, []string{"-passive", "a.com", "b.com"}},
		// -flag=value form keeps its value attached
		{[]string{"a.com", "-t=50"}, []string{"-t=50", "a.com"}},
		// value flag at the very end has no value to take
		{[]string{"a.com", "-o"}, []string{"-o", "a.com"}},
		{nil, nil},
	}
	for _, c := range cases {
		if got := reorderArgs(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("reorderArgs(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestLoadReader(t *testing.T) {
	got, err := LoadReader(strings.NewReader(" example.com \n# comment\nexample.com\napi.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadReader = %v, want %v", got, want)
	}
}

// TestAtLeast pins the clamp that keeps a zero pool size from hanging every
// module on an unbuffered job channel.
func TestAtLeast(t *testing.T) {
	for _, c := range []struct{ v, floor, want int }{
		{0, 1, 1}, {-5, 1, 1}, {1, 1, 1}, {300, 1, 300},
	} {
		if got := atLeast(c.v, c.floor); got != c.want {
			t.Errorf("atLeast(%d, %d) = %d, want %d", c.v, c.floor, got, c.want)
		}
	}
}

// TestClamp pins both ends: the floor keeps a zero pool from hanging, the
// ceiling keeps a mistyped "-t 3000000" from exhausting the host.
func TestClamp(t *testing.T) {
	for _, c := range []struct {
		name                    string
		v, floor, ceiling, want int
	}{
		{"below floor", -5, 1, 100, 1},
		{"at floor", 1, 1, 100, 1},
		{"inside range", 42, 1, 100, 42},
		{"at ceiling", 100, 1, 100, 100},
		{"above ceiling", 1 << 30, 1, 100, 100},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := clamp(c.v, c.floor, c.ceiling); got != c.want {
				t.Errorf("clamp(%d, %d, %d) = %d, want %d", c.v, c.floor, c.ceiling, got, c.want)
			}
		})
	}
}

// TestLoadClampsResourceFlags checks the ceilings are actually wired into the
// parsed Options, not just present as constants.
func TestLoadClampsResourceFlags(t *testing.T) {
	cfg, err := loadForTest(t, "example.com",
		"-t", "9999999", "-T", "9999999", "-timeout", "9999999", "-max-hosts", "999999999")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Opts.Workers != maxWorkers {
		t.Errorf("Workers = %d, want %d", cfg.Opts.Workers, maxWorkers)
	}
	if cfg.Opts.Concurrency != maxConcurrency {
		t.Errorf("Concurrency = %d, want %d", cfg.Opts.Concurrency, maxConcurrency)
	}
	if cfg.TimeoutS != maxTimeoutSeconds {
		t.Errorf("TimeoutS = %d, want %d", cfg.TimeoutS, maxTimeoutSeconds)
	}
	if cfg.Opts.MaxHosts != maxHostsCeiling {
		t.Errorf("MaxHosts = %d, want %d", cfg.Opts.MaxHosts, maxHostsCeiling)
	}
}

func TestNormalizeResolvers(t *testing.T) {
	got := normalizeResolvers([]string{"1.1.1.1", " 8.8.8.8:5353 ", "", "  "})
	want := []string{"1.1.1.1:53", "8.8.8.8:5353"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalizeResolvers = %v, want %v", got, want)
	}
}

func TestLoadFullConfiguration(t *testing.T) {
	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	wordlist := filepath.Join(dir, "words.txt")
	resolvers := filepath.Join(dir, "resolvers.txt")
	if err := os.WriteFile(targets, []byte("https://Example.com/path\napi.example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wordlist, []byte("admin\napi\nadmin\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolvers, []byte("1.1.1.1\n8.8.8.8:5353\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadForTest(t,
		"api.example.com",
		"-l", targets,
		"-m", "DNS,http,crawl",
		"-p", "80,443",
		"-t", "0",
		"-T", "0",
		"-timeout", "0",
		"-w", wordlist,
		"-r", resolvers,
		"-rate", "25",
		"-include", "extra.test,EXTRA.test",
		"-exclude", "admin.example.com",
		"-max-hosts", "0",
		"-crawl-depth", "-1",
		"-crawl-max", "0",
		"-scan-all-ips",
		"-ports-subs",
		"-probe-both",
		"-active",
		"-passive",
		"-probe-subs=false",
		"-screenshot",
		"-chrome", "chrome",
		"-o", "custom-results",
		"-format", "html",
		"-emit", "urls",
		"-webhook", " https://hooks.example.test ",
		"-no-color",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.Targets, []string{"example.com", "api.example.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	if !cfg.Silent || !cfg.NoColor || cfg.Emit != "urls" || cfg.Format != "html" ||
		cfg.Output != "custom-results" || cfg.Webhook != "https://hooks.example.test" {
		t.Fatalf("top-level config = %#v", cfg)
	}
	opts := cfg.Opts
	if opts.Workers != 1 || opts.Concurrency != 1 || opts.Timeout.Seconds() != 1 ||
		opts.MaxHosts != 1 || opts.CrawlDepth != 0 || opts.CrawlMax != 1 {
		t.Fatalf("clamped options = %#v", opts)
	}
	if !opts.ScanAllIPs || !opts.PortsSubs || !opts.ProbeBoth || !opts.Active ||
		!opts.PassiveOnly || opts.ProbeSubs || !opts.Screenshot || opts.ChromePath != "chrome" {
		t.Fatalf("boolean options = %#v", opts)
	}
	if got, want := opts.Ports, []int{80, 443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ports = %v, want %v", got, want)
	}
	if got, want := opts.Wordlist, []string{"admin", "api"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("wordlist = %v, want %v", got, want)
	}
	if got, want := opts.Resolvers, []string{"1.1.1.1:53", "8.8.8.8:5353"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("resolvers = %v, want %v", got, want)
	}
	if got, want := opts.Include, []string{"extra.test"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("include = %v, want %v", got, want)
	}
	if !opts.Modules["dns"] || !opts.Modules["http"] || !opts.Modules["crawl"] || len(opts.Modules) != 3 {
		t.Fatalf("modules = %v", opts.Modules)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := [][]string{
		{"-m", "unknown", "example.com"},
		{"-format", "xml", "example.com"},
		{"-emit", "cookies", "example.com"},
		{"-include", "bad host", "example.com"},
		{"-p", "not-a-port", "example.com"},
		{"-w", filepath.Join(t.TempDir(), "missing.txt"), "example.com"},
	}
	for _, args := range tests {
		if _, err := loadForTest(t, args...); err == nil {
			t.Errorf("Load(%v) succeeded, want error", args)
		}
	}
}

func TestLoadLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lines.txt")
	if err := os.WriteFile(path, []byte(" one \n# ignored\none\ntwo\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadLines(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"one", "two"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadLines = %v, want %v", got, want)
	}
	if _, err := LoadLines(path + ".missing"); err == nil {
		t.Fatal("LoadLines accepted missing file")
	}
}

func loadForTest(t *testing.T, args ...string) (*Config, error) {
	t.Helper()
	oldArgs, oldFlags := os.Args, flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("nexprowl-test", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = append([]string{"nexprowl"}, args...)
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
	})
	return Load()
}

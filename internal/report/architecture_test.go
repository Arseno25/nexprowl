package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arseno25/nexprowl/internal/scanner"
)

func TestArchitectureDiagramEmpty(t *testing.T) {
	r := &scanner.Result{Target: "bare.example"}
	g := BuildArchitectureGraph(r)
	d := g.Mermaid()
	if !strings.Contains(d, "graph TD") {
		t.Fatal("missing graph header")
	}
	if !strings.Contains(d, "bare.example") {
		t.Fatal("missing root node")
	}
	if !strings.Contains(d, "classDef root") {
		t.Fatal("missing classDef")
	}
	// no subgraphs for empty result
	if strings.Contains(d, "subgraph") {
		t.Fatalf("empty result should have no subgraphs:\n%s", d)
	}
}

func TestArchitectureDiagramFull(t *testing.T) {
	results := richResults()
	d := BuildArchitectureGraph(results[0]).Mermaid()

	for _, want := range []string{
		"graph TD",
		"DNS infrastructure",
		"Network",
		"Subdomains",
		"Web services",
		"Security findings",
		"example.com",
		"api.example.com",
		"192.0.2.1",
		"AS64500",
		"Cloudflare",
		"GitHub Pages",
		"dangling",
		"AXFR open",
		"classDef danger",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("diagram missing %q", want)
		}
	}
}

func TestArchitectureDiagramTruncation(t *testing.T) {
	r := &scanner.Result{Target: "trunc.example", IPs: []string{"10.0.0.1"}}
	for i := 0; i < 20; i++ {
		r.Subdomains = append(r.Subdomains, scanner.Subdomain{
			Host: strings.Repeat("s", i+1) + ".trunc.example",
		})
	}
	d := BuildArchitectureGraph(r).Mermaid()
	if !strings.Contains(d, "+8 more") {
		t.Errorf("expected truncation marker '+8 more' in:\n%s", d)
	}
}

func TestMermaidSafe(t *testing.T) {
	for in, want := range map[string]string{
		`He said "hello"`:        "He said 'hello'",
		`a\b`:                    "a/b",
		"<script>alert</script>": "(script)alert(/script)",
		"`code`":                 "'code'",
		"a & b":                  "a + b",
	} {
		if got := mermaidSafe(in); got != want {
			t.Errorf("mermaidSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestArchTrim(t *testing.T) {
	if got := archTrim("short", 10); got != "short" {
		t.Errorf("archTrim(short) = %q", got)
	}
	if got := archTrim("hello world!", 6); got != "hello…" {
		t.Errorf("archTrim(long) = %q", got)
	}
}

func TestArchitectureCompanionPath(t *testing.T) {
	for in, want := range map[string]string{
		"results/out.html": "results/out-architecture.md",
		"results/out.json": "results/out-architecture.md",
		"report.csv":       "report-architecture.md",
	} {
		if got := architectureCompanionPath(in); got != want {
			t.Errorf("architectureCompanionPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteArchitectureMD(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "architecture.md")
	results := richResults()
	if err := writeArchitectureMD(path, results); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	md := string(body)
	for _, want := range []string{
		"# Target architecture",
		"```mermaid",
		"graph TD",
		"example.com",
		"Legend",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("architecture.md missing %q", want)
		}
	}
}

func TestBrList(t *testing.T) {
	items := []string{"a.ns", "b.ns", "c.ns", "d.ns", "e.ns"}
	got := brList(items, 3)
	if !strings.Contains(got, "a.ns") || !strings.Contains(got, "+2 more") {
		t.Errorf("brList = %q", got)
	}
	if brList(nil, 5) != "" {
		t.Error("brList(nil) should be empty")
	}
}

func TestHTMLContainsArchSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arch.html")
	results := richResults()
	if err := writeHTML(path, results); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	for _, want := range []string{
		"Architecture map",
		`class="arch-cy"`,
		"cytoscape",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}

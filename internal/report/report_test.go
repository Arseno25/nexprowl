package report

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"nexprowl/internal/scanner"
)

func TestWriteHTML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	results := []*scanner.Result{{
		Target:     `<script>alert("x")</script>`,
		DurationMs: 42,
		IPs:        []string{"192.0.2.1"},
		Ports:      []scanner.Port{{Port: 443, Service: "https"}},
		Web:        []scanner.WebResult{{URL: "https://example.com", Status: 200, Title: "Example"}},
	}}

	if err := writeHTML(path, results); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	for _, want := range []string{"Scan report", "https://example.com", "192.0.2.1", "&lt;script&gt;"} {
		if !strings.Contains(html, want) {
			t.Errorf("report does not contain %q", want)
		}
	}
	if strings.Contains(html, `<script>alert("x")</script>`) {
		t.Error("target was not HTML-escaped")
	}
}

func TestNotifyWebhook(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = r.Method == http.MethodPost && r.Header.Get("Content-Type") == "application/json"
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	if err := NotifyWebhook(t.Context(), server.URL, map[string]bool{"ok": true}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("webhook was not called")
	}
}

func TestRunHistoryDiffAndEmit(t *testing.T) {
	root := t.TempDir()
	oldPath := filepath.Join(root, "old")
	newPath := filepath.Join(root, "new")
	oldResults := []*scanner.Result{{Target: "example.com", Subdomains: []scanner.Subdomain{{Host: "www.example.com"}}}}
	newResults := []*scanner.Result{{Target: "example.com", Subdomains: []scanner.Subdomain{
		{Host: "www.example.com"}, {Host: "api.example.com"},
	}}}
	if _, err := Save(oldPath, "", oldResults); err != nil {
		t.Fatal(err)
	}
	if _, err := Save(newPath, "", newResults); err != nil {
		t.Fatal(err)
	}
	diff, err := ComparePaths(oldPath, newPath)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Changed || len(diff.Added["subdomains"]) != 1 || diff.Added["subdomains"][0] != "api.example.com" {
		t.Fatalf("unexpected diff: %#v", diff)
	}
	var out bytes.Buffer
	if err := Emit(&out, "subdomains", newResults); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "api.example.com\nwww.example.com\n" {
		t.Fatalf("emit = %q", got)
	}
	path := ResolveOutputPath("results", time.Date(2026, 7, 30, 12, 34, 56, 789000000, time.UTC))
	if path != filepath.Join("results", "20260730-123456-789") {
		t.Fatalf("resolved path = %q", path)
	}
}

func TestSaveCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results", "report.html")
	if _, err := Save(path, "", []*scanner.Result{{Target: "example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("saved report: %v", err)
	}
}

func TestAllReportFormats(t *testing.T) {
	results := richResults()
	tests := map[string][]string{
		"json":  {`"target": "example.com"`},
		"jsonl": {`"target":"example.com"`},
		"csv":   {"target,host,ips", "api.example.com"},
		"md":    {"# NexProwl recon report", "Takeover candidates", `pipe\|title`},
		"html":  {"NexProwl reconnaissance report", "api.example.com"},
		"txt":   {"═══ example.com", "takeover?:"},
	}
	for extension, wants := range tests {
		path := filepath.Join(t.TempDir(), "report."+extension)
		files, err := Save(path, "", results)
		if err != nil {
			t.Fatalf("%s: %v", extension, err)
		}
		if !reflect.DeepEqual(files, []string{path}) {
			t.Fatalf("%s files = %v", extension, files)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range wants {
			if !strings.Contains(string(body), want) {
				t.Errorf("%s report missing %q", extension, want)
			}
		}
	}
}

func TestInferFormatArtifactDirAndHelpers(t *testing.T) {
	tests := map[string]Format{
		"a.json": FormatJSON, "a.ndjson": FormatJSONL, "a.csv": FormatCSV,
		"a.markdown": FormatMD, "a.htm": FormatHTML, "a.txt": FormatTXT,
		"a.unknown": FormatJSON,
	}
	for path, want := range tests {
		if got := InferFormat(path); got != want {
			t.Errorf("InferFormat(%q) = %q, want %q", path, got, want)
		}
	}
	if got := ArtifactDir(filepath.Join("out", "report.html")); got != filepath.Join("out", "screenshots") {
		t.Errorf("file ArtifactDir = %q", got)
	}
	if got := ArtifactDir("results/run"); got != filepath.Join("results", "run", "screenshots") {
		t.Errorf("directory ArtifactDir = %q", got)
	}
	if got := sanitizeFileName(`a/b:c`); got != "a_b_c" {
		t.Errorf("sanitizeFileName = %q", got)
	}
	if got := mdCell("a|b\nc"); got != `a\|b c` {
		t.Errorf("mdCell = %q", got)
	}
}

func TestEmitModes(t *testing.T) {
	results := richResults()
	wants := map[string][]string{
		"subdomains": {"api.example.com"},
		"urls":       {"https://example.com"},
		"hostports":  {"example.com:443"},
		"ips":        {"192.0.2.1", "2001:db8::1", "192.0.2.2"},
		"endpoints":  {"https://example.com/api"},
	}
	for mode, expected := range wants {
		var out bytes.Buffer
		if err := Emit(&out, mode, results); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		for _, want := range expected {
			if !strings.Contains(out.String(), want+"\n") {
				t.Errorf("%s output %q missing %q", mode, out.String(), want)
			}
		}
	}
	var jsonl bytes.Buffer
	if err := Emit(&jsonl, "jsonl", results); err != nil {
		t.Fatal(err)
	}
	var decoded scanner.Result
	if err := json.Unmarshal(jsonl.Bytes(), &decoded); err != nil || decoded.Target != "example.com" {
		t.Fatalf("jsonl = %q, %v", jsonl.String(), err)
	}
}

func TestDiffStringWriteAndLoadErrors(t *testing.T) {
	diff := &Diff{
		Old: "old", New: "new", Changed: true,
		Added:   map[string][]string{"urls": {"https://new.example.com"}},
		Removed: map[string][]string{"urls": {"https://old.example.com"}},
	}
	text := diff.String()
	for _, want := range []string{"NexProwl diff", "urls: +1 -1", "+ https://new.example.com", "- https://old.example.com"} {
		if !strings.Contains(text, want) {
			t.Errorf("diff text missing %q", want)
		}
	}
	path := filepath.Join(t.TempDir(), "nested", "diff.json")
	if err := WriteDiff(path, diff); err != nil {
		t.Fatal(err)
	}
	if loaded, err := os.ReadFile(path); err != nil || !strings.Contains(string(loaded), `"changed": true`) {
		t.Fatalf("written diff = %q, %v", loaded, err)
	}
	unchanged := (&Diff{Added: map[string][]string{}, Removed: map[string][]string{}}).String()
	if !strings.Contains(unchanged, "no changes") {
		t.Errorf("unchanged diff = %q", unchanged)
	}
	if _, err := loadResults(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing results path accepted")
	}
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, "invalid.json"), []byte(`{`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadResults(empty); err == nil {
		t.Fatal("invalid results directory accepted")
	}
}

func TestWebhookErrorsAndDisabled(t *testing.T) {
	if err := NotifyWebhook(t.Context(), "", make(chan int)); err != nil {
		t.Fatalf("disabled webhook = %v", err)
	}
	if err := NotifyWebhook(t.Context(), "https://example.test", make(chan int)); err == nil {
		t.Fatal("unmarshalable webhook payload accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer server.Close()
	if err := NotifyWebhook(t.Context(), server.URL, map[string]bool{"ok": false}); err == nil ||
		!strings.Contains(err.Error(), "status 403") {
		t.Fatalf("webhook error = %v", err)
	}
}

func richResults() []*scanner.Result {
	return []*scanner.Result{{
		Target: "example.com", DurationMs: 1250, Error: "sample error",
		IPs: []string{"192.0.2.1"},
		DNS: &scanner.DNSResult{
			A: []string{"192.0.2.1"}, AAAA: []string{"2001:db8::1"},
			MX: []string{"mail.example.com"}, CAA: []string{"0 issue letsencrypt.org"},
			SPF: []string{"v=spf1 -all"}, DMARC: []string{"v=DMARC1; p=reject"},
		},
		ZoneTransfer: []scanner.AXFREntry{{Server: "ns.example.com", Records: []string{"example.com SOA ns.example.com"}}},
		Subdomains: []scanner.Subdomain{{
			Host: "api.example.com", IPs: []string{"192.0.2.2"},
			CNAME: "api.host.test", Source: "test",
		}},
		Ports: []scanner.Port{{Host: "example.com", IP: "192.0.2.1", Port: 443, Service: "https", Banner: "hello|world"}},
		Web: []scanner.WebResult{{
			URL: "https://example.com", Host: "example.com", Status: 200,
			Title: "pipe|title", Server: "nginx", Technologies: []string{"Go"},
			WAF: "Cloudflare", CDN: "Cloudflare", Screenshot: "screenshots/a.png",
		}},
		VHosts: []scanner.VHost{{Host: "admin.example.com", Status: 403, Size: 100, Title: "Denied"}},
		TLS:    &scanner.TLSResult{Version: "TLS 1.3", Cipher: "TEST", ValidTo: "2030-01-01", Expired: true},
		TLSHosts: []scanner.TLSResult{{
			Host: "example.com", Port: 443, Version: "TLS 1.3", ValidTo: "2030-01-01",
		}},
		Takeovers: []scanner.TakeoverHit{{Host: "old.example.com", CNAME: "old.github.io", Service: "GitHub Pages"}},
		Endpoints: []scanner.Endpoint{{URL: "https://example.com/api", Source: "html", Depth: 1}},
		Sources:   []scanner.SourceStatus{{Name: "test", Found: 1}},
		Networks:  []scanner.NetworkInfo{{IP: "192.0.2.1", ASN: "AS64500", Owner: "Example"}},
		Errors:    []string{"sample error"},
	}}
}

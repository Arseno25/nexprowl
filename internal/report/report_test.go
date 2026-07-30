package report

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dscan/internal/scanner"
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

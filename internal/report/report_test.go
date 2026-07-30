package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

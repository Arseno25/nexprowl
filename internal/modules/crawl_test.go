package modules

import (
	"testing"

	"dscan/internal/scanner"
)

func TestNormalizeCrawlURL(t *testing.T) {
	sc := scanner.NewScanContext("example.com", &scanner.Options{}, nil)
	got, ok := normalizeCrawlURL("https://api.example.com/v1?q=1#frag", nil, sc)
	if !ok || got != "https://api.example.com/v1?q=1" {
		t.Fatalf("got %q, %v", got, ok)
	}
	for _, raw := range []string{
		"https://example.net/out", "javascript:alert(1)", "https://example.com/logo.png",
	} {
		if _, ok := normalizeCrawlURL(raw, nil, sc); ok {
			t.Errorf("accepted %q", raw)
		}
	}
}

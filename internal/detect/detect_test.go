package detect

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTitle(t *testing.T) {
	cases := map[string]string{
		"<title>Hello</title>":              "Hello",
		"<TITLE>Hello</TITLE>":              "Hello",
		"<title>\n  spaced   out\n</title>": "spaced out",
		`<title id="x">attrs</title>`:       "attrs",
		"<title>a</title><title>b</title>":  "a",
		"no title here":                     "",
		"<title>unclosed":                   "",
	}
	for html, want := range cases {
		if got := Title(html); got != want {
			t.Errorf("Title(%q) = %q, want %q", html, got, want)
		}
	}
}

// TestTitleTruncationIsValidUTF8 pins the rune-safe cut: slicing by byte
// splits a multi-byte character and puts invalid UTF-8 into the report.
func TestTitleTruncationIsValidUTF8(t *testing.T) {
	got := Title("<title>" + strings.Repeat("é", 200) + "</title>")
	if !utf8.ValidString(got) {
		t.Fatal("truncated title is not valid UTF-8")
	}
	if n := utf8.RuneCountInString(got); n != 120 {
		t.Fatalf("truncated to %d runes, want 120", n)
	}
}

func TestMatchTakeoverSuffixBoundary(t *testing.T) {
	if fp := MatchTakeover("mybucket.s3.amazonaws.com"); fp == nil {
		t.Error("real amazonaws.com CNAME not matched")
	}
	if fp := MatchTakeover("MyApp.HerokuApp.Com."); fp == nil {
		t.Error("match must be case- and trailing-dot-insensitive")
	}
	// The suffix must align with a label boundary.
	for _, cname := range []string{
		"evil-amazonaws.com.attacker.net",
		"notamazonaws.com",
		"github.io.attacker.net",
		"",
	} {
		if fp := MatchTakeover(cname); fp != nil {
			t.Errorf("MatchTakeover(%q) matched %s, want no match", cname, fp.Service)
		}
	}
}

func TestMatchesBody(t *testing.T) {
	fp := MatchTakeover("user.github.io")
	if fp == nil {
		t.Fatal("github.io fingerprint missing")
	}
	if !fp.MatchesBody("<h1>There isn't a GitHub Pages site here.</h1>") {
		t.Error("unclaimed-page marker not matched (case-insensitively)")
	}
	if fp.MatchesBody("<h1>Welcome to my blog</h1>") {
		t.Error("a live site must not match the unclaimed-page marker")
	}
	// A fingerprint with no body marker can never confirm via body.
	empty := &TakeoverFingerprint{Suffix: "x.test", Service: "X"}
	if empty.MatchesBody("anything at all") {
		t.Error("empty Body must never match")
	}
}

func TestWAFAndCDN(t *testing.T) {
	if got := CDN("cloudflare"); got != "Cloudflare" {
		t.Errorf("CDN(cloudflare) = %q", got)
	}
	if got := CDN("nginx"); got != "" {
		t.Errorf("CDN(nginx) = %q, want empty", got)
	}
	if WAF("Server: nginx\n") != "" {
		t.Error("plain nginx must not be flagged as a WAF")
	}
}

func TestTechnologyServicesAndSignatureCounts(t *testing.T) {
	got := Tech(
		"Server: nginx\nX-Powered-By: PHP/8.3\n",
		`<script src="/wp-content/app.js"></script>`,
	)
	joined := strings.Join(got, ",")
	for _, want := range []string{"Nginx", "PHP", "WordPress"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Tech = %v, missing %s", got, want)
		}
	}
	if got := ServiceName(443); got != "https" {
		t.Errorf("ServiceName(443) = %q", got)
	}
	if ServiceName(65000) != "" {
		t.Error("unknown port received a service name")
	}
	if !WantsBanner(22) || WantsBanner(443) {
		t.Error("banner-port classification is inconsistent")
	}
	tech, waf, takeover := SignatureCounts()
	if tech == 0 || waf == 0 || takeover == 0 {
		t.Fatalf("empty signature database: tech=%d waf=%d takeover=%d", tech, waf, takeover)
	}
}

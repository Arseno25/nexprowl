package scanner

import (
	"net/http"
	"testing"
)

func TestParseProxyURL(t *testing.T) {
	valid := []string{
		"http://127.0.0.1:8080",
		"https://proxy.example:3128",
		"socks5://127.0.0.1:9050",
		"socks5h://127.0.0.1:9050",
		"socks5://user:pass@127.0.0.1:9050", // RFC 1929 auth via userinfo
	}
	for _, raw := range valid {
		u, err := ParseProxyURL(raw)
		if err != nil || u == nil {
			t.Errorf("ParseProxyURL(%q) = %v, %v; want valid URL", raw, u, err)
		}
	}

	if u, err := ParseProxyURL(""); u != nil || err != nil {
		t.Errorf("ParseProxyURL(\"\") = %v, %v; want nil, nil", u, err)
	}

	invalid := []string{
		"ftp://127.0.0.1:21",       // unsupported scheme
		"http://",                  // missing host
		"socks5://",                // missing host
		"://nohost",                // unparseable
		"http://127.0.0.1:badport", // invalid port
	}
	for _, raw := range invalid {
		if u, err := ParseProxyURL(raw); err == nil {
			t.Errorf("ParseProxyURL(%q) = %v, nil; want error", raw, u)
		}
	}
}

func TestApplyProxy(t *testing.T) {
	// Empty proxy URL must leave the transport untouched.
	tr := &http.Transport{}
	if err := ApplyProxy(tr, ""); err != nil || tr.Proxy != nil {
		t.Fatalf("ApplyProxy(empty): Proxy set = %v, err = %v; want untouched", tr.Proxy != nil, err)
	}

	// A valid URL installs a Proxy func that always returns that URL.
	tr = &http.Transport{}
	if err := ApplyProxy(tr, "socks5://127.0.0.1:9050"); err != nil {
		t.Fatalf("ApplyProxy(socks5): %v", err)
	}
	if tr.Proxy == nil {
		t.Fatal("ApplyProxy(socks5): transport.Proxy is nil")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	u, err := tr.Proxy(req)
	if err != nil || u == nil || u.Scheme != "socks5" || u.Host != "127.0.0.1:9050" {
		t.Fatalf("Proxy(req) = %v, %v; want socks5://127.0.0.1:9050", u, err)
	}

	// An invalid URL reports an error and leaves the transport untouched.
	tr = &http.Transport{}
	if err := ApplyProxy(tr, "ftp://bad"); err == nil || tr.Proxy != nil {
		t.Fatalf("ApplyProxy(ftp): Proxy set = %v, err = %v; want error, untouched", tr.Proxy != nil, err)
	}
}

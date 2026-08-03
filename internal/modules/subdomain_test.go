package modules

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Arseno25/nexprowl/internal/scanner"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestPassiveSourceParsers(t *testing.T) {
	bodies := map[string]string{
		"crt.sh":           `[{"name_value":"*.a.example.com\nb.example.com"}]`,
		"certspotter.com":  `[{"dns_names":["*.c.example.com"]}]`,
		"alienvault.com":   `{"passive_dns":[{"hostname":"d.example.com"}]}`,
		"hackertarget.com": "e.example.com,192.0.2.1\ninvalid\n",
		"jldc.me":          `["f.example.com"]`,
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		for host, body := range bodies {
			if strings.Contains(req.URL.Host, host) {
				return testHTTPResponse(http.StatusOK, body), nil
			}
		}
		return nil, errors.New("unexpected URL: " + req.URL.String())
	})}

	tests := []struct {
		name string
		fn   func(context.Context, *http.Client, string) ([]string, error)
		want []string
	}{
		{"crt.sh", fetchCrtSh, []string{"a.example.com", "b.example.com"}},
		{"certspotter", fetchCertSpotter, []string{"c.example.com"}},
		{"otx", fetchOTX, []string{"d.example.com"}},
		{"hackertarget", fetchHackerTarget, []string{"e.example.com"}},
		{"anubis", fetchAnubis, []string{"f.example.com"}},
	}
	for _, test := range tests {
		got, err := test.fn(t.Context(), client, "example.com")
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestHTTPGetHeadersAndStatus(t *testing.T) {
	var gotAPIKey, gotAgent string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotAPIKey = req.Header.Get("APIKEY")
		gotAgent = req.Header.Get("User-Agent")
		if req.URL.Path == "/error" {
			return testHTTPResponse(http.StatusTooManyRequests, "slow down"), nil
		}
		return testHTTPResponse(http.StatusOK, "ok"), nil
	})}
	body, err := httpGetHeaders(t.Context(), client, "https://source.test/ok", map[string]string{"APIKEY": "secret"})
	if err != nil || string(body) != "ok" || gotAPIKey != "secret" || !strings.Contains(gotAgent, "NexProwl/") {
		t.Fatalf("httpGetHeaders body=%q err=%v key=%q agent=%q", body, err, gotAPIKey, gotAgent)
	}
	if _, err := httpGet(t.Context(), client, "https://source.test/error"); err == nil {
		t.Fatal("non-200 response was accepted")
	}
	broken := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})}
	if _, err := httpGet(t.Context(), broken, "https://source.test"); err == nil {
		t.Fatal("transport error was ignored")
	}
}

func TestConfiguredPassiveSources(t *testing.T) {
	t.Setenv("NEXPROWL_SECURITYTRAILS_KEY", "st")
	t.Setenv("NEXPROWL_VIRUSTOTAL_KEY", "vt")
	t.Setenv("NEXPROWL_SHODAN_KEY", "sh")
	sources := configuredPassiveSources()
	if len(sources) != len(passiveSources)+3 {
		t.Fatalf("sources = %d, want %d", len(sources), len(passiveSources)+3)
	}

	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(req.URL.Host, "securitytrails"):
			if req.Header.Get("APIKEY") != "st" {
				t.Error("SecurityTrails API key header missing")
			}
			return testHTTPResponse(http.StatusOK, `{"subdomains":["api"]}`), nil
		case strings.Contains(req.URL.Host, "virustotal"):
			if req.Header.Get("x-apikey") != "vt" {
				t.Error("VirusTotal API key header missing")
			}
			return testHTTPResponse(http.StatusOK, `{"data":[{"id":"vt.example.com"}]}`), nil
		case strings.Contains(req.URL.Host, "shodan"):
			if req.URL.Query().Get("key") != "sh" {
				t.Error("Shodan API key query missing")
			}
			return testHTTPResponse(http.StatusOK, `{"subdomains":["mail"]}`), nil
		default:
			return nil, errors.New("unexpected source")
		}
	})}
	want := map[string][]string{
		"securitytrails": {"api.example.com"},
		"virustotal":     {"vt.example.com"},
		"shodan":         {"mail.example.com"},
	}
	for _, source := range sources {
		expected, ok := want[source.name]
		if !ok {
			continue
		}
		got, err := source.fetch(t.Context(), client, "example.com")
		if err != nil || !reflect.DeepEqual(got, expected) {
			t.Errorf("%s = %v, %v; want %v", source.name, got, err, expected)
		}
	}
}

func TestPassiveSourceInvalidJSON(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testHTTPResponse(http.StatusOK, `{`), nil
	})}
	for _, fn := range []func(context.Context, *http.Client, string) ([]string, error){
		fetchCrtSh, fetchCertSpotter, fetchOTX, fetchAnubis,
	} {
		if _, err := fn(t.Context(), client, "example.com"); err == nil {
			t.Error("invalid JSON was accepted")
		}
	}
}

func TestSubdomainRunWithDeterministicSources(t *testing.T) {
	oldSources := passiveSources
	passiveSources = []passiveSource{
		{"ok", func(context.Context, *http.Client, string) ([]string, error) {
			return []string{"api.localhost", "wild.localhost", "outside.test", "bad @localhost"}, nil
		}},
		{"offline", func(context.Context, *http.Client, string) ([]string, error) {
			return nil, errors.New("offline")
		}},
	}
	t.Cleanup(func() { passiveSources = oldSources })
	t.Setenv("NEXPROWL_SECURITYTRAILS_KEY", "")
	t.Setenv("NEXPROWL_VIRUSTOTAL_KEY", "")
	t.Setenv("NEXPROWL_SHODAN_KEY", "")

	sc := scanner.NewScanContext("localhost", &scanner.Options{
		Workers: 2, Timeout: 50 * time.Millisecond, PassiveOnly: true, MaxHosts: 10,
	}, nil)
	sc.Result.TLS = &scanner.TLSResult{SANs: []string{"tls.localhost", "outside.test"}}
	if err := (Subdomain{}).Run(t.Context(), sc); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(sc.Result.Subdomains))
	for _, sub := range sc.Result.Subdomains {
		got = append(got, sub.Host)
	}
	want := []string{"api.localhost", "tls.localhost", "wild.localhost"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("subdomains = %v, want %v", got, want)
	}
	if len(sc.Result.Sources) != 2 || sc.Result.Sources[0].Name != "offline" ||
		sc.Result.Sources[0].Error == "" {
		t.Fatalf("source health = %#v", sc.Result.Sources)
	}
}

func testHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

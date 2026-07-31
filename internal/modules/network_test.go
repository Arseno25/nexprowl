package modules

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"nexprowl/internal/scanner"
)

func TestGrabBanner(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		_, _ = io.WriteString(server, "SSH-2.0-NexProwl_Test\r\nignored")
	}()
	if got := grabBanner(client); got != "SSH-2.0-NexProwl_Test" {
		t.Fatalf("banner = %q", got)
	}
}

func TestActiveWAFProbe(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
		want   string
	}{
		{http.StatusNotAcceptable, "", "Generic WAF (blocked probe)"},
		{http.StatusForbidden, "Request blocked by web application firewall", "Generic WAF (block page)"},
		{http.StatusOK, "welcome", ""},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(test.status)
			_, _ = io.WriteString(w, test.body)
		}))
		got := activeWAFProbe(t.Context(), server.Client(), server.URL)
		server.Close()
		if got != test.want {
			t.Errorf("activeWAFProbe(%d) = %q, want %q", test.status, got, test.want)
		}
	}
}

func TestHTTPURLAndRedirectScope(t *testing.T) {
	if got := webURL("http", "2001:db8::1", 80); got != "http://[2001:db8::1]" {
		t.Errorf("IPv6 URL = %q", got)
	}
	if got := webURL("https", "example.com", 8443); got != "https://example.com:8443" {
		t.Errorf("custom-port URL = %q", got)
	}
	if got := preferredSchemes(443)[0]; got != "https" {
		t.Errorf("port 443 preferred %q", got)
	}
	if got := preferredSchemes(8080)[0]; got != "http" {
		t.Errorf("port 8080 preferred %q", got)
	}

	sc := scanner.NewScanContext("example.com", testOptions(), nil)
	client := newScopedHTTPClient(sc)
	inside, _ := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
	outside, _ := http.NewRequest(http.MethodGet, "https://outside.test", nil)
	if err := client.CheckRedirect(inside, nil); err != nil {
		t.Errorf("in-scope redirect rejected: %v", err)
	}
	if err := client.CheckRedirect(outside, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("out-of-scope redirect error = %v", err)
	}
	baseClient := newHTTPClient(time.Second)
	if baseClient.Timeout != 4*time.Second || baseClient.Transport == nil {
		t.Fatalf("base HTTP client = %#v", baseClient)
	}
	via := make([]*http.Request, 5)
	if err := baseClient.CheckRedirect(inside, via); !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("redirect limit error = %v", err)
	}
}

func TestVHostModelAndProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, strings.Repeat("x", len(r.Host)+10))
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)

	result := probeVHost(t.Context(), server.Client(), u.Host, "http", "admin.example.com", time.Second, "")
	if !result.ok || result.status != http.StatusNotFound || result.size != len("admin.example.com")+10 {
		t.Fatalf("probe result = %#v", result)
	}
	model := buildVhostModel(t.Context(), server.Client(), u.Host, "http", "example.com", time.Second, "")
	if !model.ok || !model.isNoise("candidate.example.com", http.StatusNotFound, len("candidate.example.com")+10) {
		t.Fatalf("model = %#v", model)
	}
	if model.isNoise("candidate.example.com", http.StatusOK, len("candidate.example.com")+10) {
		t.Error("different status classified as noise")
	}
	if got := randHex(6); len(got) != 12 {
		t.Fatalf("randHex length = %d", len(got))
	}
	sniClient := newVHostClient("admin.example.com", time.Second, "")
	transport := sniClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.ServerName != "admin.example.com" {
		t.Fatalf("vhost TLS client = %#v", transport.TLSClientConfig)
	}

	sc := scanner.NewScanContext("example.com", testOptions(), nil)
	if err := (VHost{}).Run(context.Background(), sc); err != nil || len(sc.Result.VHosts) != 0 {
		t.Fatalf("empty VHost run = %#v, %v", sc.Result.VHosts, err)
	}
}

func TestTLSProbeAndEnrichment(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	ip, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)

	sc := scanner.NewScanContext("example.com", testOptions(), nil)
	result := probeTLS(t.Context(), sc, "example.com", ip, port)
	if result == nil || result.Version == "" || result.Cipher == "" || result.Port != port {
		t.Fatalf("TLS result = %#v", result)
	}
	sc.Result.Web = []scanner.WebResult{{
		URL: server.URL, Host: "example.com", IP: ip, Scheme: "https", Port: port,
	}}
	if err := (TLS{}).Run(t.Context(), sc); err != nil {
		t.Fatal(err)
	}
	if len(sc.Result.TLSHosts) != 1 {
		t.Fatalf("TLS hosts = %#v", sc.Result.TLSHosts)
	}

	versions := map[uint16]string{
		0x0301: "TLS 1.0 (insecure)",
		0x0302: "TLS 1.1 (insecure)",
		0x0303: "TLS 1.2",
		0x0304: "TLS 1.3",
		0x9999: "0x9999",
	}
	for version, want := range versions {
		if got := tlsVersionName(version); got != want {
			t.Errorf("tlsVersionName(%x) = %q", version, got)
		}
	}

	var events []scanner.Event
	logContext := scanner.NewScanContext("example.com", testOptions(), func(event scanner.Event) {
		events = append(events, event)
	})
	logTLS(logContext, &scanner.TLSResult{
		Version: "TLS 1.2", Cipher: "TEST", Issuer: "Test CA",
		ValidFrom: "2020-01-01", ValidTo: "2021-01-01", Expired: true,
		SANs: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"},
	})
	if len(events) != 4 || !strings.Contains(events[2].Message, "EXPIRED") ||
		!strings.Contains(events[3].Message, "SANs (9)") {
		t.Fatalf("TLS log events = %#v", events)
	}

	seedContext := scanner.NewScanContext("127.0.0.2", &scanner.Options{
		Timeout: 20 * time.Millisecond,
	}, nil)
	if err := (TLSSeed{}).Run(t.Context(), seedContext); err != nil {
		t.Fatal(err)
	}
}

func TestTakeoverBodyAndEmptyRuns(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Scheme == "https" {
			return nil, errors.New("TLS unavailable")
		}
		return testHTTPResponse(http.StatusOK, "unclaimed page"), nil
	})}
	sc := scanner.NewScanContext("example.com", testOptions(), nil)
	if got := fetchBody(t.Context(), client, "api.example.com", sc); got != "unclaimed page" {
		t.Fatalf("fetchBody = %q", got)
	}
	if err := (Takeover{}).Run(t.Context(), sc); err != nil {
		t.Fatal(err)
	}
	sc.Result.Subdomains = []scanner.Subdomain{{Host: "api.example.com", CNAME: "live.example.net"}}
	if err := (Takeover{}).Run(t.Context(), sc); err != nil || len(sc.Result.Takeovers) != 0 {
		t.Fatalf("non-candidate takeover = %#v, %v", sc.Result.Takeovers, err)
	}
}

func TestScopedHTTPClientProxy(t *testing.T) {
	opts := testOptions()
	opts.ProxyURL = "socks5://127.0.0.1:9050"
	sc := scanner.NewScanContext("example.com", opts, nil)

	client := newScopedHTTPClient(sc)
	transport := client.Transport.(*http.Transport)
	if transport.Proxy == nil {
		t.Fatal("proxied scoped client has no Proxy func")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	u, err := transport.Proxy(req)
	if err != nil || u == nil || u.Scheme != "socks5" || u.Host != "127.0.0.1:9050" {
		t.Fatalf("Proxy(req) = %v, %v; want socks5://127.0.0.1:9050", u, err)
	}

	// Without -proxy the transport must stay direct.
	sc = scanner.NewScanContext("example.com", testOptions(), nil)
	if tr := newScopedHTTPClient(sc).Transport.(*http.Transport); tr.Proxy != nil {
		t.Fatal("direct scoped client has Proxy set")
	}
}

// TestHTTPClientForIPWithProxy pins the interaction between -proxy and
// -scan-all-ips: through a proxy the dialer must reach the proxy, so the
// pinned-IP dial override must be skipped (IP pinning is the proxy's job).
func TestHTTPClientForIPWithProxy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())

	// Without proxy: DialContext ignores the hostname and dials the pinned IP.
	sc := scanner.NewScanContext("example.com", testOptions(), nil)
	pinned := newHTTPClientForIP(sc, "127.0.0.1").Transport.(*http.Transport)
	conn, err := pinned.DialContext(t.Context(), "tcp", net.JoinHostPort("unresolvable.invalid", port))
	if err != nil {
		t.Fatalf("pinned dial should reach the pinned IP: %v", err)
	}
	conn.Close()

	// With proxy: no pinning — dialing an unresolvable name must fail
	// (the stock dialer runs, proving the override was skipped).
	opts := testOptions()
	opts.ProxyURL = "socks5://127.0.0.1:9050"
	sc = scanner.NewScanContext("example.com", opts, nil)
	proxied := newHTTPClientForIP(sc, "127.0.0.1").Transport.(*http.Transport)
	if proxied.Proxy == nil {
		t.Fatal("proxied IP client lost the Proxy func")
	}
	if conn, err := proxied.DialContext(t.Context(), "tcp", net.JoinHostPort("unresolvable.invalid", port)); err == nil {
		conn.Close()
		t.Fatal("proxied client still pins the IP; override must be skipped")
	}
}

func TestVHostClientProxy(t *testing.T) {
	client := newVHostClient("admin.example.com", time.Second, "socks5://127.0.0.1:9050")
	transport := client.Transport.(*http.Transport)
	if transport.Proxy == nil {
		t.Fatal("vhost client has no Proxy func")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.ServerName != "admin.example.com" {
		t.Fatal("vhost client lost its SNI pinning when proxied")
	}

	// Empty proxy URL keeps the transport direct.
	direct := newVHostClient("", time.Second, "").Transport.(*http.Transport)
	if direct.Proxy != nil {
		t.Fatal("direct vhost client has Proxy set")
	}
}

func testOptions() *scanner.Options {
	return &scanner.Options{
		Workers: 2, Timeout: time.Second, MaxHosts: 100,
		CrawlDepth: 1, CrawlMax: 20,
	}
}

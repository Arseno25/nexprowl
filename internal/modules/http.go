package modules

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"nexprowl/internal/detect"
	"nexprowl/internal/scanner"
)

const maxBodyRead = 512 << 10 // 512KB — enough for title + tech signatures

// HTTP probes web services (httpx technique): HTTPS first, HTTP fallback,
// on the target and optionally every live subdomain. Runs tech detection
// (wappalyzer) and WAF detection (wafw00f passive + active).
type HTTP struct{}

func (HTTP) Name() string { return "http" }

type probeOutcome struct {
	web     *scanner.WebResult
	headers http.Header
	body    string
}

type webCandidate struct {
	host string
	ip   string
	port int
}

// headerBlob flattens response headers into the "Key: value\n" text the
// tech/WAF signature databases are written against.
func (o *probeOutcome) headerBlob() string {
	var sb strings.Builder
	for k, vv := range o.headers {
		for _, v := range vv {
			sb.WriteString(k + ": " + v + "\n")
		}
	}
	return sb.String()
}

func (HTTP) Run(ctx context.Context, sc *scanner.ScanContext) error {
	client := newScopedHTTPClient(sc)

	hosts := []string{sc.Target}
	if sc.Opts.ProbeSubs {
		seen := map[string]bool{sc.Target: true}
		for _, sub := range sc.Result.Subdomains {
			if seen[sub.Host] {
				continue
			}
			seen[sub.Host] = true
			if len(sub.IPs) > 0 || sub.CNAME != "" {
				hosts = append(hosts, sub.Host)
			}
		}
	}
	for _, vhost := range sc.Result.VHosts {
		if sc.InScope(vhost.Host) {
			hosts = append(hosts, vhost.Host)
		}
	}

	seenCandidates := map[string]bool{}
	var candidates []webCandidate
	addCandidate := func(host, ip string, port int) {
		key := host + "|" + ip + "|" + strconv.Itoa(port)
		if !seenCandidates[key] {
			seenCandidates[key] = true
			candidates = append(candidates, webCandidate{host: host, ip: ip, port: port})
		}
	}
	for _, host := range scanner.UniqueSorted(hosts) {
		addCandidate(host, "", 80)
		addCandidate(host, "", 443)
	}
	for _, p := range sc.Result.Ports {
		host := p.Host
		if host == "" {
			host = sc.Target
		}
		addCandidate(host, p.IP, p.Port)
	}

	jobs := make(chan webCandidate, sc.Opts.Workers)
	results := make(chan *scanner.WebResult, len(candidates)*2)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for candidate := range jobs {
			candidateClient := client
			if candidate.ip != "" {
				candidateClient = newHTTPClientForIP(sc, candidate.ip)
			}
			schemes := preferredSchemes(candidate.port)
			for i, scheme := range schemes {
				sc.Limit(ctx)
				rawURL := webURL(scheme, candidate.host, candidate.port)
				out, ok := probeOne(ctx, candidateClient, rawURL, sc.Opts.Timeout)
				if !ok {
					continue
				}

				// Signature analysis happens here so response bodies are not
				// retained for every host at once.
				wr, blob := out.web, out.headerBlob()
				wr.Host, wr.IP, wr.Scheme, wr.Port = candidate.host, candidate.ip, scheme, candidate.port
				wr.Technologies = detect.Tech(blob, out.body)
				wr.WAF = detect.WAF(blob)
				wr.CDN = detect.CDN(wr.Server)
				wr.FaviconHash = faviconHash(ctx, candidateClient, rawURL, sc)
				results <- wr

				sc.Found("live", "%s → %d %q", wr.URL, wr.Status, wr.Title)
				if !sc.Opts.ProbeBoth || i == len(schemes)-1 {
					break
				}
			}
		}
	}

	for i := 0; i < min(sc.Opts.Workers, len(candidates)); i++ {
		wg.Add(1)
		go worker()
	}
hostLoop:
	for _, candidate := range candidates {
		select {
		case jobs <- candidate:
		case <-ctx.Done():
			break hostLoop
		}
	}
	close(jobs)
	wg.Wait()
	close(results)

	for wr := range results {
		sc.Result.Web = append(sc.Result.Web, *wr)
	}

	sort.Slice(sc.Result.Web, func(i, j int) bool {
		a, b := sc.Result.Web[i], sc.Result.Web[j]
		if (a.Host == sc.Target) != (b.Host == sc.Target) {
			return a.Host == sc.Target
		}
		return a.URL < b.URL
	})

	if len(sc.Result.Web) > 0 {
		main := &sc.Result.Web[0]
		if len(main.Technologies) > 0 {
			sc.Log(scanner.LevelSuccess, "tech: %s", strings.Join(main.Technologies, ", "))
		}
		if main.WAF != "" {
			sc.Log(scanner.LevelWarn, "WAF: %s", main.WAF)
		} else if sc.Opts.Active {
			if waf := activeWAFProbe(ctx, client, main.URL); waf != "" {
				main.WAF = waf
				sc.Log(scanner.LevelWarn, "WAF: %s (active probe)", waf)
			}
		}
	}
	sc.Log(scanner.LevelSuccess, "%d live web services", len(sc.Result.Web))
	return nil
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout + 3*time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     10 * time.Second,
			DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func newScopedHTTPClient(sc *scanner.ScanContext) *http.Client {
	client := newHTTPClient(sc.Opts.Timeout)
	if err := scanner.ApplyProxy(client.Transport.(*http.Transport), sc.Opts.ProxyURL); err != nil {
		sc.Log(scanner.LevelInfo, "http: proxy disabled: %s", err)
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !sc.InScope(req.URL.Hostname()) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return client
}

func newHTTPClientForIP(sc *scanner.ScanContext, ip string) *http.Client {
	timeout := sc.Opts.Timeout
	client := newScopedHTTPClient(sc)
	if sc.Opts.ProxyURL != "" {
		// Through a proxy the transport must dial the proxy, not the pinned
		// IP — routing is the proxy's job, so IP pinning is meaningless.
		return client
	}
	transport := client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, net.JoinHostPort(ip, port))
	}
	return client
}

func probeOne(ctx context.Context, client *http.Client, url string, timeout time.Duration) (*probeOutcome, bool) {
	c, cancel := context.WithTimeout(ctx, timeout+3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(c, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

	wr := &scanner.WebResult{
		URL:         url,
		Status:      resp.StatusCode,
		Server:      resp.Header.Get("Server"),
		PoweredBy:   resp.Header.Get("X-Powered-By"),
		ContentLen:  resp.ContentLength,
		ContentType: resp.Header.Get("Content-Type"),
		ResponseMs:  time.Since(start).Milliseconds(),
		Title:       detect.Title(string(body)),
	}
	sum := sha256.Sum256(body)
	wr.BodyHash = hex.EncodeToString(sum[:])
	if resp.Request.URL.String() != url {
		wr.Redirect = resp.Request.URL.String()
	} else if loc := resp.Header.Get("Location"); loc != "" {
		wr.Redirect = loc
	}
	return &probeOutcome{web: wr, headers: resp.Header, body: string(body)}, true
}

func preferredSchemes(port int) []string {
	switch port {
	case 443, 4443, 7443, 8443, 9443, 10443:
		return []string{"https", "http"}
	default:
		return []string{"http", "https"}
	}
}

func webURL(scheme, host string, port int) string {
	h := host
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		h = net.JoinHostPort(host, strconv.Itoa(port))
	} else if strings.Contains(host, ":") {
		h = "[" + strings.Trim(host, "[]") + "]"
	}
	return (&url.URL{Scheme: scheme, Host: h}).String()
}

func faviconHash(ctx context.Context, client *http.Client, rawURL string, sc *scanner.ScanContext) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.Path, u.RawQuery = "/favicon.ico", ""
	sc.Limit(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if len(body) == 0 {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// activeWAFProbe sends a malicious payload; a blocked response or a block
// page indicates a WAF even when headers reveal nothing (wafw00f active).
func activeWAFProbe(ctx context.Context, client *http.Client, baseURL string) string {
	payload := baseURL + "/?nexprowl=%3Cscript%3Ealert(1)%3C/script%3E%20AND%201=1%20UNION%20SELECT%20null--"
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, payload, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 NexProwl/"+scanner.Version)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	switch resp.StatusCode {
	case 406, 501, 999:
		return "Generic WAF (blocked probe)"
	}
	lower := strings.ToLower(string(body))
	for _, kw := range []string{
		"access denied", "request blocked", "web application firewall",
		"malicious request", "attack detected", "not acceptable",
		"incapsula incident", "cloudflare ray id", "mod_security",
	} {
		if strings.Contains(lower, kw) {
			return "Generic WAF (block page)"
		}
	}
	return ""
}

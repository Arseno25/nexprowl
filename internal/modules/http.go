package modules

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"dscan/internal/detect"
	"dscan/internal/scanner"
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

func (HTTP) Run(ctx context.Context, sc *scanner.ScanContext) error {
	client := newHTTPClient(sc.Opts.Timeout)

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

	jobs := make(chan string, sc.Opts.Workers)
	results := make(chan probeOutcome, len(hosts))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for host := range jobs {
			sc.Limit(ctx)
			out, ok := probeOne(ctx, client, "https://"+host, sc.Opts.Timeout)
			if !ok {
				sc.Limit(ctx)
				out, ok = probeOne(ctx, client, "http://"+host, sc.Opts.Timeout)
			}
			if !ok {
				continue
			}
			results <- *out

			wr := out.web
			if host == sc.Target {
				sc.Found("live", "%s → %d %q [%s]", wr.URL, wr.Status, wr.Title, wr.Server)
			} else {
				sc.Found("live", "%s → %d %q", wr.URL, wr.Status, wr.Title)
			}
		}
	}

	for i := 0; i < min(sc.Opts.Workers, len(hosts)); i++ {
		wg.Add(1)
		go worker()
	}
hostLoop:
	for _, h := range hosts {
		select {
		case jobs <- h:
		case <-ctx.Done():
			break hostLoop
		}
	}
	close(jobs)
	wg.Wait()
	close(results)

	for out := range results {
		wr := out.web

		// signature analysis (wappalyzer + wafw00f passive)
		var sb strings.Builder
		for k, vv := range out.headers {
			for _, v := range vv {
				sb.WriteString(k + ": " + v + "\n")
			}
		}
		headerBlob := sb.String()
		wr.Technologies = detect.Tech(headerBlob, out.body)
		wr.WAF = detect.WAF(headerBlob)
		wr.CDN = detect.CDN(wr.Server)

		sc.Result.Web = append(sc.Result.Web, *wr)
	}

	// main target first
	for i := range sc.Result.Web {
		if sc.Result.Web[i].URL == "https://"+sc.Target || sc.Result.Web[i].URL == "http://"+sc.Target {
			sc.Result.Web[0], sc.Result.Web[i] = sc.Result.Web[i], sc.Result.Web[0]
			break
		}
	}

	if len(sc.Result.Web) > 0 {
		main := &sc.Result.Web[0]
		if len(main.Technologies) > 0 {
			sc.Log(scanner.LevelSuccess, "tech: %s", strings.Join(main.Technologies, ", "))
		}
		if main.WAF != "" {
			sc.Log(scanner.LevelWarn, "WAF: %s", main.WAF)
		} else if waf := activeWAFProbe(ctx, client, main.URL); waf != "" {
			main.WAF = waf
			sc.Log(scanner.LevelWarn, "WAF: %s (active probe)", waf)
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

func probeOne(ctx context.Context, client *http.Client, url string, timeout time.Duration) (*probeOutcome, bool) {
	c, cancel := context.WithTimeout(ctx, timeout+3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(c, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))

	wr := &scanner.WebResult{
		URL:        url,
		Status:     resp.StatusCode,
		Server:     resp.Header.Get("Server"),
		PoweredBy:  resp.Header.Get("X-Powered-By"),
		ContentLen: resp.ContentLength,
		Title:      detect.Title(string(body)),
	}
	if resp.Request.URL.String() != url {
		wr.Redirect = resp.Request.URL.String()
	} else if loc := resp.Header.Get("Location"); loc != "" {
		wr.Redirect = loc
	}
	return &probeOutcome{web: wr, headers: resp.Header, body: string(body)}, true
}

// activeWAFProbe sends a malicious payload; a blocked response or a block
// page indicates a WAF even when headers reveal nothing (wafw00f active).
func activeWAFProbe(ctx context.Context, client *http.Client, baseURL string) string {
	payload := baseURL + "/?dscan=%3Cscript%3Ealert(1)%3C/script%3E%20AND%201=1%20UNION%20SELECT%20null--"
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, payload, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 dscan/1.0")
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

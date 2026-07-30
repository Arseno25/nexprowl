package modules

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"dscan/internal/detect"
	"dscan/internal/scanner"
)

// VHost discovers virtual hosts on the target IP via Host-header /
// SNI fuzzing (gobuster vhost technique): hosts that serve different
// content than the baseline (random host) are virtual hosts — often
// hidden admin panels or staging sites not present in DNS.
type VHost struct{}

func (VHost) Name() string { return "vhost" }

const vhostMaxBody = 256 << 10

// vhostModel filters wildcard-vhost noise (e.g. Cloudflare returning an
// error page for EVERY Host header). Error pages often embed the hostname,
// so size grows linearly with hostname length — two baseline samples of
// different lengths let us predict the expected noise size: size ≈ a + b·len(host).
type vhostModel struct {
	ok     bool
	status int
	a, b   float64 // size model: size ≈ a + b*len(host)
}

// isNoise reports whether a response matches the wildcard baseline.
func (m vhostModel) isNoise(host string, status, size int) bool {
	if !m.ok || status != m.status {
		return false
	}
	expected := m.a + m.b*float64(len(host))
	diff := float64(size) - expected
	if diff < 0 {
		diff = -diff
	}
	return diff <= 32 // ±32 bytes tolerance around the predicted noise size
}

// buildVhostModel samples two random hosts of different lengths.
func buildVhostModel(ctx context.Context, ip, scheme, target string, timeout time.Duration) vhostModel {
	h1 := randHex(6) + "." + target        // short random
	h2 := randHex(12) + ".x." + target     // long random (different length)
	r1 := probeVHost(ctx, ip, scheme, h1, timeout)
	r2 := probeVHost(ctx, ip, scheme, h2, timeout)
	if !r1.ok || !r2.ok {
		return vhostModel{}
	}
	b := float64(r2.size-r1.size) / float64(len(h2)-len(h1))
	a := float64(r1.size) - b*float64(len(h1))
	return vhostModel{ok: true, status: r1.status, a: a, b: b}
}

func randHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func (VHost) Run(ctx context.Context, sc *scanner.ScanContext) error {
	if len(sc.Result.IPs) == 0 || len(sc.Opts.Wordlist) == 0 {
		sc.Log(scanner.LevelInfo, "vhost: skipped (no IP or wordlist)")
		return nil
	}
	ip := sc.Result.IPs[0]

	// wildcard-vhost baseline models per scheme
	modelHTTP := buildVhostModel(ctx, ip, "http", sc.Target, sc.Opts.Timeout)
	modelHTTPS := buildVhostModel(ctx, ip, "https", sc.Target, sc.Opts.Timeout)
	if !modelHTTP.ok && !modelHTTPS.ok {
		sc.Log(scanner.LevelInfo, "vhost: skipped (no web service on ip)")
		return nil
	}

	// skip hosts that already resolve publicly — vhost discovery is for
	// hidden services, not known subdomains
	known := map[string]bool{}
	for _, sub := range sc.Result.Subdomains {
		known[sub.Host] = true
	}

	jobs := make(chan string, sc.Opts.Workers)
	var wg sync.WaitGroup
	var mu sync.Mutex

	worker := func() {
		defer wg.Done()
		for word := range jobs {
			host := word + "." + sc.Target
			if known[host] {
				continue
			}
			for _, scheme := range []string{"http", "https"} {
				model := modelHTTP
				if scheme == "https" {
					model = modelHTTPS
				}
				if !model.ok {
					continue
				}
				sc.Limit(ctx)
				res := probeVHost(ctx, ip, scheme, host, sc.Opts.Timeout)
				if !res.ok {
					continue
				}
				// matches wildcard baseline (status + size model) = noise
				if model.isNoise(host, res.status, res.size) {
					continue
				}
				vh := scanner.VHost{Host: host, Status: res.status, Size: int64(res.size), Title: res.title}
				mu.Lock()
				sc.Result.VHosts = append(sc.Result.VHosts, vh)
				mu.Unlock()
				sc.Found("vhost", "%s → %d (%d bytes) %q [%s]", host, res.status, res.size, res.title, scheme)
				break // one scheme hit is enough
			}
		}
	}

	for i := 0; i < min(sc.Opts.Workers, len(sc.Opts.Wordlist)); i++ {
		wg.Add(1)
		go worker()
	}
wordLoop:
	for _, w := range sc.Opts.Wordlist {
		select {
		case jobs <- w:
		case <-ctx.Done():
			break wordLoop
		}
	}
	close(jobs)
	wg.Wait()

	if len(sc.Result.VHosts) > 0 {
		sc.Log(scanner.LevelSuccess, "%d virtual hosts discovered", len(sc.Result.VHosts))
	} else {
		sc.Log(scanner.LevelInfo, "no hidden vhosts")
	}
	return nil
}

type vhostResult struct {
	ok     bool
	status int
	size   int
	title  string
}

// probeVHost requests scheme://ip/ with a custom Host header.
// For HTTPS the SNI (TLS ServerName) is set to the vhost — this is how
// shared hosting / CDNs route virtual hosts.
func probeVHost(ctx context.Context, ip, scheme, hostHeader string, timeout time.Duration) vhostResult {
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostHeader, // SNI-based vhost routing
		},
	}
	client := &http.Client{
		Timeout:   timeout + 2*time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	c, cancel := context.WithTimeout(ctx, timeout+2*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s://%s/", scheme, ip)
	req, err := http.NewRequestWithContext(c, http.MethodGet, url, nil)
	if err != nil {
		return vhostResult{}
	}
	req.Host = hostHeader // Host-header routing
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) dscan/1.0")
	req.Header.Set("Accept", "text/html,*/*;q=0.8")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return vhostResult{}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, vhostMaxBody))

	return vhostResult{
		ok:     true,
		status: resp.StatusCode,
		size:   len(body),
		title:  detect.Title(string(body)),
	}
}

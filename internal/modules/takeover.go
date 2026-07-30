package modules

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"nexprowl/internal/detect"
	"nexprowl/internal/scanner"
)

// takeoverBodyRead caps the body pulled for fingerprint matching. Service
// "unclaimed" pages are tiny; anything larger is a real site.
const takeoverBodyRead = 64 << 10

// isNXDomain reports whether a lookup failed because the name does not
// exist. Every other failure (timeout, SERVFAIL, dead resolver) says
// nothing about the CNAME being claimable and must not be reported.
func isNXDomain(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// Takeover finds dangling CNAMEs pointing at claimable services
// (subjack/nuclei technique). Two independent signals:
//
//  1. the CNAME target is NXDOMAIN — the zone was deleted outright;
//  2. the CNAME resolves, but the service answers with its "nothing is
//     registered here" page. Providers like GitHub Pages and Shopify keep
//     resolving dangling names, so signal 1 alone misses most real hits.
type Takeover struct{}

func (Takeover) Name() string { return "takeover" }

type takeoverCandidate struct {
	host  string
	cname string
	fp    *detect.TakeoverFingerprint
}

func (Takeover) Run(ctx context.Context, sc *scanner.ScanContext) error {
	if len(sc.Result.Subdomains) == 0 {
		return nil
	}

	var cands []takeoverCandidate
	for _, sub := range sc.Result.Subdomains {
		if sub.CNAME == "" {
			continue
		}
		if fp := detect.MatchTakeover(sub.CNAME); fp != nil {
			cands = append(cands, takeoverCandidate{sub.Host, sub.CNAME, fp})
		}
	}
	if len(cands) == 0 {
		sc.Log(scanner.LevelInfo, "no takeover candidates")
		return nil
	}

	client := newScopedHTTPClient(sc)
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, sc.Opts.Workers)
	r := sc.Resolver()

	for _, c := range cands {
		wg.Add(1)
		go func(c takeoverCandidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctxT, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
			_, err := r.LookupHost(ctxT, c.cname)
			cancel()

			note := ""
			switch {
			case isNXDomain(err):
				note = "CNAME does not resolve (NXDOMAIN) — likely claimable"
			case err == nil && c.fp.MatchesBody(fetchBody(ctx, client, c.host, sc)):
				note = "service returned its unclaimed-name page — likely claimable"
			default:
				return
			}

			hit := scanner.TakeoverHit{
				Host:    c.host,
				CNAME:   c.cname,
				Service: c.fp.Service,
				Note:    note,
			}
			mu.Lock()
			sc.Result.Takeovers = append(sc.Result.Takeovers, hit)
			mu.Unlock()
			sc.Found("takeover", "%s → %s (%s)", c.host, c.cname, c.fp.Service)
		}(c)
	}
	wg.Wait()

	if len(sc.Result.Takeovers) > 0 {
		sc.Log(scanner.LevelWarn, "%d possible subdomain takeovers!", len(sc.Result.Takeovers))
	}
	return nil
}

// fetchBody GETs the host over HTTPS, falling back to HTTP, and returns the
// body (empty on any failure — a failure is not evidence of a takeover).
func fetchBody(ctx context.Context, client *http.Client, host string, sc *scanner.ScanContext) string {
	for _, url := range []string{"https://" + host, "http://" + host} {
		sc.Limit(ctx)
		c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout+3*time.Second)
		req, err := http.NewRequestWithContext(c, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 NexProwl/"+scanner.Version)
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, takeoverBodyRead))
		resp.Body.Close()
		cancel()
		if len(body) > 0 {
			return string(body)
		}
	}
	return ""
}

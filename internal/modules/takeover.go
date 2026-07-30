package modules

import (
	"context"
	"sync"

	"dscan/internal/detect"
	"dscan/internal/scanner"
)

// Takeover finds dangling CNAMEs pointing at claimable services
// (subjack/nuclei technique): CNAME matches a known fingerprint AND
// the CNAME target fails to resolve → potentially claimable.
type Takeover struct{}

func (Takeover) Name() string { return "takeover" }

func (Takeover) Run(ctx context.Context, sc *scanner.ScanContext) error {
	if len(sc.Result.Subdomains) == 0 {
		return nil
	}

	type candidate struct {
		host, cname, service string
	}
	var cands []candidate
	for _, sub := range sc.Result.Subdomains {
		if sub.CNAME == "" {
			continue
		}
		if service := detect.MatchTakeover(sub.CNAME); service != "" {
			cands = append(cands, candidate{sub.Host, sub.CNAME, service})
		}
	}
	if len(cands) == 0 {
		sc.Log(scanner.LevelInfo, "no takeover candidates")
		return nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, sc.Opts.Workers)
	r := sc.Resolver()

	for _, c := range cands {
		wg.Add(1)
		go func(c candidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctxT, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
			_, err := r.LookupHost(ctxT, c.cname)
			cancel()
			if err != nil {
				hit := scanner.TakeoverHit{
					Host:    c.host,
					CNAME:   c.cname,
					Service: c.service,
					Note:    "CNAME does not resolve (NXDOMAIN) — likely claimable",
				}
				mu.Lock()
				sc.Result.Takeovers = append(sc.Result.Takeovers, hit)
				mu.Unlock()
				sc.Found("takeover", "%s → %s (%s)", c.host, c.cname, c.service)
			}
		}(c)
	}
	wg.Wait()

	if len(sc.Result.Takeovers) > 0 {
		sc.Log(scanner.LevelWarn, "%d possible subdomain takeovers!", len(sc.Result.Takeovers))
	}
	return nil
}

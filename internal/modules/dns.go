package modules

import (
	"context"
	"strings"
	"sync"

	"dscan/internal/scanner"
)

// DNS enumerates A, AAAA, MX, NS, TXT, CNAME in parallel
// (dnsrecon/dig technique) and runs wildcard detection.
type DNS struct{}

func (DNS) Name() string { return "dns" }

func (DNS) Run(ctx context.Context, sc *scanner.ScanContext) error {
	r := sc.Resolver()
	out := &scanner.DNSResult{}
	var wg sync.WaitGroup
	var mu sync.Mutex

	lookup := func(fn func(c context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
			defer cancel()
			fn(c)
		}()
	}

	lookup(func(c context.Context) {
		if ips, err := r.LookupIP(c, "ip4", sc.Target); err == nil {
			mu.Lock()
			for _, ip := range ips {
				out.A = append(out.A, ip.String())
			}
			mu.Unlock()
		}
	})
	lookup(func(c context.Context) {
		if ips, err := r.LookupIP(c, "ip6", sc.Target); err == nil {
			mu.Lock()
			for _, ip := range ips {
				out.AAAA = append(out.AAAA, ip.String())
			}
			mu.Unlock()
		}
	})
	lookup(func(c context.Context) {
		if mxs, err := r.LookupMX(c, sc.Target); err == nil {
			mu.Lock()
			for _, mx := range mxs {
				if mx.Host == "." {
					out.MX = append(out.MX, "(null MX — no email)")
				} else {
					out.MX = append(out.MX, mx.Host)
				}
			}
			mu.Unlock()
		}
	})
	lookup(func(c context.Context) {
		if nss, err := r.LookupNS(c, sc.Target); err == nil {
			mu.Lock()
			for _, ns := range nss {
				out.NS = append(out.NS, ns.Host)
			}
			mu.Unlock()
		}
	})
	lookup(func(c context.Context) {
		if txts, err := r.LookupTXT(c, sc.Target); err == nil {
			mu.Lock()
			out.TXT = txts
			mu.Unlock()
		}
	})
	lookup(func(c context.Context) {
		if cname, err := r.LookupCNAME(c, sc.Target); err == nil && cname != "" && cname != sc.Target+"." {
			mu.Lock()
			out.CNAME = cname
			mu.Unlock()
		}
	})
	wg.Wait()

	out.A = scanner.UniqueSorted(out.A)
	out.AAAA = scanner.UniqueSorted(out.AAAA)
	out.MX = scanner.UniqueSorted(out.MX)
	out.NS = scanner.UniqueSorted(out.NS)
	sc.Result.DNS = out
	sc.Result.IPs = out.A

	if len(out.A) > 0 {
		sc.Log(scanner.LevelSuccess, "A     %v", out.A)
	}
	if len(out.AAAA) > 0 {
		sc.Log(scanner.LevelSuccess, "AAAA  %v", out.AAAA)
	}
	if len(out.MX) > 0 {
		sc.Log(scanner.LevelSuccess, "MX    %v", out.MX)
	}
	if len(out.NS) > 0 {
		sc.Log(scanner.LevelSuccess, "NS    %v", out.NS)
	}
	if out.CNAME != "" {
		sc.Log(scanner.LevelSuccess, "CNAME %s", out.CNAME)
	}

	sc.DetectWildcard(ctx)

	// Zone transfer attempt (dnsrecon technique) — uses raw DNS wire protocol.
	if hosts := tryZoneTransfer(ctx, sc); len(hosts) > 0 {
		sc.Result.Subdomains = append(sc.Result.Subdomains, axfrHostsToSubdomains(sc.Target, hosts)...)
	}
	return nil
}

// axfrHostsToSubdomains converts hostnames extracted from a dumped zone
// into Subdomain entries (deduped against existing results by the sub module).
func axfrHostsToSubdomains(target string, hosts []string) []scanner.Subdomain {
	seen := map[string]bool{}
	var out []scanner.Subdomain
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if h == "" || h == target || seen[h] {
			continue
		}
		if !strings.HasSuffix(h, "."+target) {
			continue
		}
		seen[h] = true
		out = append(out, scanner.Subdomain{Host: h, Source: "axfr"})
	}
	return out
}

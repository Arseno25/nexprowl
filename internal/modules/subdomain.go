package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dscan/internal/scanner"
)

// Subdomain discovers subdomains via passive sources (subfinder technique)
// plus DNS bruteforce with wildcard filtering (gobuster technique).
type Subdomain struct{}

func (Subdomain) Name() string { return "sub" }

// ─── Passive sources (free, keyless) ──────────────────────

type passiveSource struct {
	name  string
	fetch func(ctx context.Context, client *http.Client, domain string) ([]string, error)
}

var passiveSources = []passiveSource{
	{"crt.sh", fetchCrtSh},
	{"certspotter", fetchCertSpotter},
	{"otx", fetchOTX},
	{"hackertarget", fetchHackerTarget},
	{"anubis", fetchAnubis},
}

func httpGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) dscan/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func fetchCrtSh(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := httpGet(ctx, client, "https://crt.sh/?q=%25."+domain+"&output=json")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		for _, name := range strings.Split(r.NameValue, "\n") {
			if name = strings.TrimPrefix(strings.TrimSpace(name), "*."); name != "" {
				out = append(out, name)
			}
		}
	}
	return out, nil
}

func fetchCertSpotter(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := httpGet(ctx, client,
		"https://api.certspotter.com/v1/issuances?domain="+domain+"&include_subdomains=true&expand=dns_names")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		for _, n := range r.DNSNames {
			if n = strings.TrimPrefix(strings.TrimSpace(n), "*."); n != "" {
				out = append(out, n)
			}
		}
	}
	return out, nil
}

func fetchOTX(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := httpGet(ctx, client,
		"https://otx.alienvault.com/api/v1/indicators/domain/"+domain+"/passive_dns")
	if err != nil {
		return nil, err
	}
	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range data.PassiveDNS {
		if r.Hostname != "" {
			out = append(out, r.Hostname)
		}
	}
	return out, nil
}

func fetchHackerTarget(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := httpGet(ctx, client, "https://api.hackertarget.com/hostsearch/?q="+domain)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if host, _, ok := strings.Cut(line, ","); ok && strings.Contains(host, ".") {
			out = append(out, strings.TrimSpace(host))
		}
	}
	return out, nil
}

func fetchAnubis(ctx context.Context, client *http.Client, domain string) ([]string, error) {
	body, err := httpGet(ctx, client, "https://jldc.me/anubis/subdomains/"+domain)
	if err != nil {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ─── Module logic ─────────────────────────────────────────

func (Subdomain) Run(ctx context.Context, sc *scanner.ScanContext) error {
	found := make(map[string]*scanner.Subdomain)
	var mu sync.Mutex

	// seed with hosts already discovered (e.g. AXFR zone dump in dns phase)
	for _, s := range sc.Result.Subdomains {
		found[s.Host] = &scanner.Subdomain{Host: s.Host, Source: s.Source}
	}

	add := func(host, source string) {
		host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
		if host == "" || host == sc.Target || !strings.HasSuffix(host, "."+sc.Target) {
			return
		}
		if strings.ContainsAny(host, " *@") {
			return
		}
		mu.Lock()
		if _, ok := found[host]; !ok {
			found[host] = &scanner.Subdomain{Host: host, Source: source}
		}
		mu.Unlock()
	}

	// Phase 1 — passive sources in parallel
	client := &http.Client{Timeout: 12 * time.Second}
	var wg sync.WaitGroup
	for _, src := range passiveSources {
		wg.Add(1)
		go func(src passiveSource) {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			hosts, err := src.fetch(c, client, sc.Target)
			if err != nil {
				return
			}
			for _, h := range hosts {
				add(h, src.name)
			}
		}(src)
	}
	wg.Wait()

	mu.Lock()
	passiveUnique := len(found)
	mu.Unlock()
	sc.Log(scanner.LevelInfo, "passive: %d unique from %d sources", passiveUnique, len(passiveSources))

	// Phase 2 — bruteforce with wildcard filtering
	if !sc.Opts.PassiveOnly && len(sc.Opts.Wordlist) > 0 {
		jobs := make(chan string, sc.Opts.Workers)
		var bwg sync.WaitGroup
		var hits int32

		worker := func() {
			defer bwg.Done()
			r := sc.Resolver()
			for word := range jobs {
				host := word + "." + sc.Target
				sc.Limit(ctx)
				c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
				ips, err := r.LookupIP(c, "ip4", host)
				cancel()
				if err != nil || len(ips) == 0 {
					continue
				}
				ipStrs := make([]string, 0, len(ips))
				for _, ip := range ips {
					ipStrs = append(ipStrs, ip.String())
				}
				if sc.IsWildcardOnly(ipStrs) {
					continue
				}
				mu.Lock()
				if e, ok := found[host]; ok {
					e.IPs = scanner.UniqueSorted(append(e.IPs, ipStrs...))
				} else {
					found[host] = &scanner.Subdomain{Host: host, IPs: scanner.UniqueSorted(ipStrs), Source: "bruteforce"}
					sc.Found("sub", "%s → %s", host, strings.Join(ipStrs, ","))
				}
				mu.Unlock()
				atomic.AddInt32(&hits, 1)
			}
		}

		n := min(sc.Opts.Workers, len(sc.Opts.Wordlist))
		for i := 0; i < n; i++ {
			bwg.Add(1)
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
		bwg.Wait()
		sc.Log(scanner.LevelInfo, "bruteforce: %d hits (%d words)", hits, len(sc.Opts.Wordlist))
	}

	// Phase 3 — resolve CNAME + IPs for every host
	mu.Lock()
	hosts := make([]*scanner.Subdomain, 0, len(found))
	for _, e := range found {
		hosts = append(hosts, e)
	}
	mu.Unlock()

	jobs := make(chan *scanner.Subdomain, sc.Opts.Workers)
	var rwg sync.WaitGroup
	resolveWorker := func() {
		defer rwg.Done()
		r := sc.Resolver()
		for e := range jobs {
			c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
			cname, _ := r.LookupCNAME(c, e.Host)
			ips, _ := r.LookupIP(c, "ip4", e.Host)
			cancel()
			if cname = strings.TrimSuffix(cname, "."); cname != "" && cname != e.Host {
				e.CNAME = cname
			}
			if len(ips) > 0 {
				ipStrs := make([]string, 0, len(ips))
				for _, ip := range ips {
					ipStrs = append(ipStrs, ip.String())
				}
				e.IPs = scanner.UniqueSorted(append(e.IPs, ipStrs...))
			}
		}
	}
	for i := 0; i < min(sc.Opts.Workers, len(hosts)); i++ {
		rwg.Add(1)
		go resolveWorker()
	}
hostLoop:
	for _, e := range hosts {
		select {
		case jobs <- e:
		case <-ctx.Done():
			break hostLoop
		}
	}
	close(jobs)
	rwg.Wait()

	out := make([]scanner.Subdomain, 0, len(hosts))
	for _, e := range hosts {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	sc.Result.Subdomains = out
	sc.Log(scanner.LevelSuccess, "%d subdomains discovered", len(out))
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

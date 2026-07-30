package modules

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

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

	for _, txt := range out.TXT {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			out.SPF = append(out.SPF, txt)
		}
	}
	if txt, err := lookupTXT(ctx, sc, "_dmarc."+sc.Target); err == nil {
		for _, value := range txt {
			if strings.HasPrefix(strings.ToLower(value), "v=dmarc1") {
				out.DMARC = append(out.DMARC, value)
			}
		}
	}
	for _, service := range []struct{ name, proto string }{
		{"sip", "tcp"}, {"sip", "udp"}, {"xmpp-server", "tcp"},
		{"autodiscover", "tcp"}, {"ldap", "tcp"},
	} {
		c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
		_, records, err := r.LookupSRV(c, service.name, service.proto, sc.Target)
		cancel()
		if err != nil {
			continue
		}
		for _, record := range records {
			out.SRV = append(out.SRV, fmt.Sprintf("_%s._%s %d %d %d %s",
				service.name, service.proto, record.Priority, record.Weight,
				record.Port, strings.TrimSuffix(record.Target, ".")))
		}
	}

	out.CAA = authoritativeValues(ctx, sc, dnsTypeCAA)
	out.SOA = authoritativeValues(ctx, sc, dnsTypeSOA)
	for _, ip := range append(append([]string{}, out.A...), out.AAAA...) {
		c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
		names, err := r.LookupAddr(c, ip)
		cancel()
		if err == nil {
			for _, name := range names {
				out.PTR = append(out.PTR, fmt.Sprintf("%s → %s", ip, strings.TrimSuffix(name, ".")))
			}
		}
		if info := lookupASN(ctx, sc, ip); info != nil {
			sc.Result.Networks = append(sc.Result.Networks, *info)
		}
	}

	out.A = scanner.UniqueSorted(out.A)
	out.AAAA = scanner.UniqueSorted(out.AAAA)
	out.MX = scanner.UniqueSorted(out.MX)
	out.NS = scanner.UniqueSorted(out.NS)
	out.CAA = scanner.UniqueSorted(out.CAA)
	out.SOA = scanner.UniqueSorted(out.SOA)
	out.SRV = scanner.UniqueSorted(out.SRV)
	out.PTR = scanner.UniqueSorted(out.PTR)
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

	// Zone transfer attempt (dnsrecon technique) — uses raw DNS wire protocol.
	if hosts := tryZoneTransfer(ctx, sc); len(hosts) > 0 {
		sc.Result.Subdomains = append(sc.Result.Subdomains, axfrHostsToSubdomains(sc.Target, hosts)...)
	}
	return nil
}

func lookupTXT(ctx context.Context, sc *scanner.ScanContext, name string) ([]string, error) {
	c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
	defer cancel()
	return sc.Resolver().LookupTXT(c, name)
}

func authoritativeValues(ctx context.Context, sc *scanner.ScanContext, qtype uint16) []string {
	ns := nameservers(ctx, sc)
	if len(ns) == 0 {
		return nil
	}
	c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
	ips, err := sc.Resolver().LookupIP(c, "ip", ns[0])
	cancel()
	if err != nil || len(ips) == 0 {
		return nil
	}
	dialer := net.Dialer{Timeout: sc.Opts.Timeout}
	c2, cancel2 := context.WithTimeout(ctx, sc.Opts.Timeout)
	defer cancel2()
	conn, err := dialer.DialContext(c2, "udp", net.JoinHostPort(ips[0].String(), "53"))
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(sc.Opts.Timeout))
	query := buildDNSQuery(sc.Target, qtype, 0x4453)
	if _, err := conn.Write(query); err != nil {
		return nil
	}
	msg := make([]byte, 64<<10)
	n, err := conn.Read(msg)
	if err != nil {
		return nil
	}
	lines, _, err := parseDNSMessage(msg[:n])
	if err != nil {
		return nil
	}
	typeName := dnsTypeName[qtype]
	var out []string
	for _, line := range lines {
		needle := " " + typeName + " "
		if i := strings.Index(line, needle); i >= 0 {
			out = append(out, line[i+len(needle):])
		}
	}
	return out
}

func lookupASN(ctx context.Context, sc *scanner.ScanContext, rawIP string) *scanner.NetworkInfo {
	ip := net.ParseIP(rawIP)
	if ip == nil || ip.To4() == nil {
		return nil
	}
	v4 := ip.To4()
	query := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	values, err := lookupTXT(ctx, sc, query)
	if err != nil || len(values) == 0 {
		return nil
	}
	parts := strings.Split(values[0], "|")
	if len(parts) < 2 {
		return nil
	}
	info := &scanner.NetworkInfo{
		IP: rawIP, ASN: strings.TrimSpace(parts[0]), Prefix: strings.TrimSpace(parts[1]),
	}
	owner, err := lookupTXT(ctx, sc, "AS"+info.ASN+".asn.cymru.com")
	if err == nil && len(owner) > 0 {
		ownerParts := strings.Split(owner[0], "|")
		if len(ownerParts) > 0 {
			info.Owner = strings.TrimSpace(ownerParts[len(ownerParts)-1])
		}
	}
	return info
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

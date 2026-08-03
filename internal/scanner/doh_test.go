package scanner

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// dohFixture serves canned dns-json answers keyed by "name|type".
type dohFixture struct {
	status  int
	answers []dohAnswer
}

func dohTestServer(t *testing.T, fixtures map[string]dohFixture) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		key := q.Get("name") + "|" + q.Get("type")
		if key == "badrequest.example|A" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"error":"Invalid name"}`)
			return
		}
		fx, ok := fixtures[key]
		if !ok {
			fx = dohFixture{status: 0} // NODATA: NOERROR, empty answer
		}
		w.Header().Set("Content-Type", "application/dns-json")
		_, _ = fmt.Fprintf(w, `{"Status":%d,"Answer":[`, fx.status)
		for i, a := range fx.answers {
			if i > 0 {
				_, _ = fmt.Fprint(w, ",")
			}
			data := strings.ReplaceAll(a.Data, `"`, `\"`)
			_, _ = fmt.Fprintf(w, `{"name":%q,"type":%d,"TTL":300,"data":"%s"}`, a.Name, a.Type, data)
		}
		_, _ = fmt.Fprint(w, `]}`)
	}))
	t.Cleanup(server.Close)
	return server
}

func dohTestResolver(server *httptest.Server) *dohResolver {
	return &dohResolver{client: server.Client(), endpoint: server.URL}
}

func testFixtures() map[string]dohFixture {
	return map[string]dohFixture{
		"example.com|A": {0, []dohAnswer{
			{Name: "example.com.", Type: dohTypeA, Data: "93.184.216.34"},
		}},
		"example.com|AAAA": {0, []dohAnswer{
			{Name: "example.com.", Type: dohTypeAAAA, Data: "2606:2800:220:1:248:1893:25c8:1946"},
		}},
		"example.com|NS": {0, []dohAnswer{
			{Name: "example.com.", Type: dohTypeNS, Data: "ns1.iana-servers.net."},
			{Name: "example.com.", Type: dohTypeNS, Data: "ns2.iana-servers.net."},
		}},
		"example.com|TXT": {0, []dohAnswer{
			{Name: "example.com.", Type: dohTypeTXT, Data: `"v=spf1 -all"`},
			// RFC 1035: one TXT record with two character-strings.
			{Name: "example.com.", Type: dohTypeTXT, Data: `"part1" "part2"`},
		}},
		// RFC 7505: a normal MX alongside a null MX; only the real one counts.
		"mail.example|MX": {0, []dohAnswer{
			{Name: "mail.example.", Type: dohTypeMX, Data: "10 mail.example.com."},
			{Name: "mail.example.", Type: dohTypeMX, Data: "0 ."},
		}},
		// RFC 7505: domain that accepts no mail publishes ONLY "0 .".
		"nullmx.example|MX": {0, []dohAnswer{
			{Name: "nullmx.example.", Type: dohTypeMX, Data: "0 ."},
		}},
		"alias.example|CNAME": {0, []dohAnswer{
			{Name: "alias.example.", Type: dohTypeCNAME, Data: "target.example."},
		}},
		// Two-hop chain: alias2 → alias → target (target has no CNAME).
		"alias2.example|CNAME": {0, []dohAnswer{
			{Name: "alias2.example.", Type: dohTypeCNAME, Data: "alias.example."},
		}},
		"_sip._tcp.example|SRV": {0, []dohAnswer{
			{Name: "_sip._tcp.example.", Type: dohTypeSRV, Data: "10 60 5060 sipserver.example."},
			// RFC 2782 §4: target "." = service decidedly not available.
			{Name: "_sip._tcp.example.", Type: dohTypeSRV, Data: "0 0 0 ."},
		}},
		"1.2.0.192.in-addr.arpa|PTR": {0, []dohAnswer{
			{Name: "1.2.0.192.in-addr.arpa.", Type: dohTypePTR, Data: "ptr.example."},
		}},
		"v6only.example|AAAA": {0, []dohAnswer{
			{Name: "v6only.example.", Type: dohTypeAAAA, Data: "2001:db8::1"},
		}},
		"nx.example|A":       {status: 3},
		"nx.example|AAAA":    {status: 3},
		"nx.example|CNAME":   {status: 3},
		"servfail.example|A": {status: 2},
	}
}

func TestDoHLookupIPAndHost(t *testing.T) {
	r := dohTestResolver(dohTestServer(t, testFixtures()))
	ctx := t.Context()

	ips, err := r.LookupIP(ctx, "ip4", "example.com")
	if err != nil || len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Fatalf("LookupIP(ip4) = %v, %v", ips, err)
	}

	ips, err = r.LookupIP(ctx, "ip6", "example.com")
	if err != nil || len(ips) != 1 || ips[0].String() != "2606:2800:220:1:248:1893:25c8:1946" {
		t.Fatalf("LookupIP(ip6) = %v, %v", ips, err)
	}

	// network "ip": A comes back empty (NODATA) → must fall back to AAAA.
	ips, err = r.LookupIP(ctx, "ip", "v6only.example")
	if err != nil || len(ips) != 1 || ips[0].String() != "2001:db8::1" {
		t.Fatalf("LookupIP(ip) v6 fallback = %v, %v", ips, err)
	}

	hosts, err := r.LookupHost(ctx, "example.com")
	if err != nil || len(hosts) != 1 || hosts[0] != "93.184.216.34" {
		t.Fatalf("LookupHost = %v, %v", hosts, err)
	}

	// NXDOMAIN → IsNotFound, mirroring net.Resolver.
	_, err = r.LookupIP(ctx, "ip4", "nx.example")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("LookupIP(nx) err = %v; want *net.DNSError IsNotFound", err)
	}

	// SERVFAIL → temporary error.
	_, err = r.LookupIP(ctx, "ip4", "servfail.example")
	if !errors.As(err, &dnsErr) || !dnsErr.IsTemporary {
		t.Fatalf("LookupIP(servfail) err = %v; want *net.DNSError IsTemporary", err)
	}

	// NODATA (NOERROR, no answers of any family) → IsNotFound like Go.
	_, err = r.LookupIP(ctx, "ip", "ghost.example")
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("LookupIP(nodata) err = %v; want IsNotFound", err)
	}
}

func TestDoHLookupMXNullFiltered(t *testing.T) {
	r := dohTestResolver(dohTestServer(t, testFixtures()))

	mxs, err := r.LookupMX(t.Context(), "mail.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(mxs) != 1 || mxs[0].Host != "mail.example.com" || mxs[0].Pref != 10 {
		t.Fatalf("LookupMX = %v; want only the real exchanger (RFC 7505 null MX filtered)", mxs)
	}

	// A null-MX-only domain accepts no mail → empty result, no error.
	mxs, err = r.LookupMX(t.Context(), "nullmx.example")
	if err != nil || len(mxs) != 0 {
		t.Fatalf("LookupMX(nullmx) = %v, %v; want empty", mxs, err)
	}
}

func TestDoHLookupNSAndTXT(t *testing.T) {
	r := dohTestResolver(dohTestServer(t, testFixtures()))

	nss, err := r.LookupNS(t.Context(), "example.com")
	if err != nil || len(nss) != 2 || nss[0].Host != "ns1.iana-servers.net" {
		t.Fatalf("LookupNS = %v, %v", nss, err)
	}

	txts, err := r.LookupTXT(t.Context(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"v=spf1 -all", "part1part2"}
	if len(txts) != 2 || txts[0] != want[0] || txts[1] != want[1] {
		t.Fatalf("LookupTXT = %q; want %q", txts, want)
	}
}

func TestDoHLookupCNAMEChain(t *testing.T) {
	r := dohTestResolver(dohTestServer(t, testFixtures()))

	got, err := r.LookupCNAME(t.Context(), "alias2.example")
	if err != nil || got != "target.example" {
		t.Fatalf("LookupCNAME(chain) = %q, %v; want target.example", got, err)
	}

	// No CNAME record → the host is its own canonical name (net.Resolver
	// behavior), NOT an error.
	got, err = r.LookupCNAME(t.Context(), "target.example")
	if err != nil || got != "target.example" {
		t.Fatalf("LookupCNAME(no cname) = %q, %v; want target.example, nil", got, err)
	}

	_, err = r.LookupCNAME(t.Context(), "nx.example")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("LookupCNAME(nx) err = %v; want IsNotFound", err)
	}
}

func TestDoHLookupSRVNullTargetFiltered(t *testing.T) {
	r := dohTestResolver(dohTestServer(t, testFixtures()))

	_, srvs, err := r.LookupSRV(t.Context(), "sip", "tcp", "example")
	if err != nil {
		t.Fatal(err)
	}
	if len(srvs) != 1 {
		t.Fatalf("LookupSRV = %v; want only the real target (RFC 2782 null target filtered)", srvs)
	}
	s := srvs[0]
	if s.Target != "sipserver.example" || s.Port != 5060 || s.Priority != 10 || s.Weight != 60 {
		t.Fatalf("LookupSRV[0] = %+v", s)
	}
}

func TestDoHLookupAddr(t *testing.T) {
	r := dohTestResolver(dohTestServer(t, testFixtures()))

	names, err := r.LookupAddr(t.Context(), "192.0.2.1")
	if err != nil || len(names) != 1 || names[0] != "ptr.example" {
		t.Fatalf("LookupAddr = %v, %v", names, err)
	}

	if _, err := r.LookupAddr(t.Context(), "not-an-ip"); err == nil {
		t.Fatal("LookupAddr(invalid) accepted the address")
	}
}

func TestDoHHTTPError(t *testing.T) {
	r := dohTestResolver(dohTestServer(t, testFixtures()))
	_, err := r.LookupIP(t.Context(), "ip4", "badrequest.example")
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("LookupIP(http 400) err = %v; want HTTP status error", err)
	}
}

func TestReverseArpa(t *testing.T) {
	v4, err := reverseArpa("192.0.2.1")
	if err != nil || v4 != "1.2.0.192.in-addr.arpa" {
		t.Fatalf("reverseArpa(v4) = %q, %v", v4, err)
	}
	// RFC 3596 §2.5: nibble-reversed ip6.arpa.
	v6, err := reverseArpa("2001:db8::1")
	want := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
	if err != nil || v6 != want {
		t.Fatalf("reverseArpa(v6) = %q, %v; want %q", v6, err, want)
	}
	if _, err := reverseArpa("junk"); err == nil {
		t.Fatal("reverseArpa(junk) accepted the input")
	}
}

func TestParseTXTData(t *testing.T) {
	for in, want := range map[string]string{
		`"v=spf1 -all"`:   "v=spf1 -all",
		`"part1" "part2"`: "part1part2",
		`"a\"b"`:          `a"b`, // escaped quote inside character-string
		"plain-unquoted":  "plain-unquoted",
		`""`:              "",
	} {
		if got := parseTXTData(in); got != want {
			t.Errorf("parseTXTData(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDoHStatusError(t *testing.T) {
	if err := dohStatusError(0); err != nil {
		t.Fatalf("NOERROR = %v", err)
	}
	var dnsErr *net.DNSError
	if err := dohStatusError(3); !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("NXDOMAIN = %v; want IsNotFound", err)
	}
	if err := dohStatusError(2); !errors.As(err, &dnsErr) || !dnsErr.IsTemporary {
		t.Fatalf("SERVFAIL = %v; want IsTemporary", err)
	}
}

// TestDoHSatisfiesResolver pins the interface contract at compile time.
func TestDoHSatisfiesResolver(t *testing.T) {
	var _ Resolver = (*dohResolver)(nil)
	var _ Resolver = (*net.Resolver)(nil)
}

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ─── DoH resolver ─────────────────────────────────────────
//
// DNS-over-HTTPS client speaking the application/dns-json API shared by
// Cloudflare (cloudflare-dns.com) and Google (dns.google). The JSON schema
// has no formal RFC, but both providers document identical behavior:
// https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
//
// Routing DNS inside HTTPS keeps queries invisible to the local network
// (no plaintext UDP/53 for a firewall or ISP to log or tamper with).
//
// Method behavior mirrors net.Resolver so callers see no difference:
//   - NXDOMAIN (RCODE 3)        → *net.DNSError{IsNotFound: true}
//   - other RCODEs              → *net.DNSError{IsTemporary: true}
//   - LookupCNAME with no CNAME → the queried host itself (canonical name)
//   - null MX  (RFC 7505)       → omitted from results
//   - null SRV target (RFC 2782)→ omitted from results

const dohEndpoint = "https://cloudflare-dns.com/dns-query"

// DNS record types used by the JSON API (IANA DNS parameters).
const (
	dohTypeA     = 1
	dohTypeNS    = 2
	dohTypeCNAME = 5
	dohTypePTR   = 12
	dohTypeMX    = 15
	dohTypeTXT   = 16
	dohTypeAAAA  = 28
	dohTypeSRV   = 33
)

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
}

// dohResolver implements Resolver against a dns-json endpoint.
type dohResolver struct {
	client   *http.Client
	endpoint string
}

func newDoHResolver() *dohResolver {
	return &dohResolver{
		client:   &http.Client{Timeout: 10 * time.Second},
		endpoint: dohEndpoint,
	}
}

// dohStatusError maps a DNS RCODE to an error mirroring net.Resolver:
// NXDOMAIN is a hard "not found", everything else is a temporary failure.
func dohStatusError(status int) error {
	switch status {
	case 0: // NOERROR
		return nil
	case 3: // NXDOMAIN
		return &net.DNSError{Err: "no such host", IsNotFound: true}
	default: // SERVFAIL(2), REFUSED(5), ...
		return &net.DNSError{Err: fmt.Sprintf("server failure (rcode %d)", status), IsTemporary: true}
	}
}

// query runs one dns-json query and fails on transport, HTTP, and RCODE
// errors — callers only see usable answers.
func (d *dohResolver) query(ctx context.Context, name, qtype string) (*dohResponse, error) {
	u := fmt.Sprintf("%s?name=%s&type=%s", d.endpoint, url.QueryEscape(name), qtype)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	var dr dohResponse
	if err := json.Unmarshal(body, &dr); err != nil {
		return nil, fmt.Errorf("doh: malformed response: %w", err)
	}
	if err := dohStatusError(dr.Status); err != nil {
		return nil, err
	}
	return &dr, nil
}

// answersOfType filters the answer section down to one record type.
func (dr *dohResponse) answersOfType(qtype int) []dohAnswer {
	var out []dohAnswer
	for _, a := range dr.Answer {
		if a.Type == qtype {
			out = append(out, a)
		}
	}
	return out
}

// parseIPs extracts A/AAAA records from an answer section.
func parseIPs(answers []dohAnswer) []net.IP {
	var ips []net.IP
	for _, a := range answers {
		if a.Type == dohTypeA || a.Type == dohTypeAAAA {
			if ip := net.ParseIP(a.Data); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

var errDoHNoData = &net.DNSError{Err: "no such host", IsNotFound: true}

func (d *dohResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	qtype := "A"
	if strings.Contains(network, "6") {
		qtype = "AAAA"
	}
	dr, err := d.query(ctx, host, qtype)
	if err != nil {
		return nil, err
	}
	ips := parseIPs(dr.Answer)
	if len(ips) == 0 && (network == "ip" || network == "ip4" || network == "ip6") {
		// network "ip" accepts either family — fall back to the other type.
		other := "AAAA"
		if qtype == "AAAA" {
			other = "A"
		}
		if dr2, err2 := d.query(ctx, host, other); err2 == nil {
			ips = parseIPs(dr2.Answer)
		}
	}
	if len(ips) == 0 {
		return nil, errDoHNoData // NODATA: host exists but has no address
	}
	return ips, nil
}

func (d *dohResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	ips, err := d.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, nil
}

func (d *dohResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	arpa, err := reverseArpa(addr)
	if err != nil {
		return nil, err
	}
	dr, err := d.query(ctx, arpa, "PTR")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range dr.answersOfType(dohTypePTR) {
		out = append(out, strings.TrimSuffix(a.Data, "."))
	}
	if len(out) == 0 {
		return nil, errDoHNoData
	}
	return out, nil
}

// reverseArpa builds the PTR query name for an IPv4 or IPv6 address.
func reverseArpa(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP: %s", addr)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", ip4[3], ip4[2], ip4[1], ip4[0]), nil
	}
	// IPv6: one nibble per label, reversed (RFC 3596 §2.5).
	ip16 := ip.To16()
	var b strings.Builder
	for i := len(ip16) - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "%x.%x.", ip16[i]&0x0f, ip16[i]>>4)
	}
	return b.String() + "ip6.arpa", nil
}

func (d *dohResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	dr, err := d.query(ctx, host, "MX")
	if err != nil {
		return nil, err
	}
	var out []*net.MX
	for _, a := range dr.answersOfType(dohTypeMX) {
		parts := strings.SplitN(a.Data, " ", 2)
		if len(parts) != 2 {
			continue
		}
		exchange := strings.TrimSuffix(parts[1], ".")
		// RFC 7505 null MX ("0 .") — domain accepts no mail; not a server.
		if exchange == "" {
			continue
		}
		pref := 0
		_, _ = fmt.Sscanf(parts[0], "%d", &pref)
		out = append(out, &net.MX{Host: exchange, Pref: uint16(pref)})
	}
	return out, nil
}

func (d *dohResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	dr, err := d.query(ctx, host, "NS")
	if err != nil {
		return nil, err
	}
	var out []*net.NS
	for _, a := range dr.answersOfType(dohTypeNS) {
		if ns := strings.TrimSuffix(a.Data, "."); ns != "" {
			out = append(out, &net.NS{Host: ns})
		}
	}
	return out, nil
}

func (d *dohResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	dr, err := d.query(ctx, host, "TXT")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range dr.answersOfType(dohTypeTXT) {
		out = append(out, parseTXTData(a.Data))
	}
	return out, nil
}

// parseTXTData flattens a dns-json TXT value into the single string
// net.LookupTXT would return: dns-json presents one record as adjacent
// quoted character-strings (RFC 1035 master format), e.g. "\"ab\" \"cd\"",
// while Go concatenates a record's character-strings ("abcd").
func parseTXTData(data string) string {
	data = strings.TrimSpace(data)
	if data == "" || data[0] != '"' {
		return data
	}
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(data); i++ {
		switch c := data[i]; {
		case c == '\\' && inQuote && i+1 < len(data): // escaped char inside quotes
			b.WriteByte(data[i+1])
			i++
		case c == '"':
			inQuote = !inQuote
		case inQuote:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func (d *dohResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	// Follow the CNAME chain like net.Resolver does; the final name after
	// zero or more CNAMEs is the canonical name. A host without any CNAME
	// is its own canonical name (not an error).
	current := strings.TrimSuffix(host, ".")
	for hops := 0; hops < 10; hops++ {
		dr, err := d.query(ctx, current, "CNAME")
		if err != nil {
			return "", err
		}
		answers := dr.answersOfType(dohTypeCNAME)
		if len(answers) == 0 {
			return current, nil
		}
		current = strings.TrimSuffix(answers[0].Data, ".")
	}
	return "", fmt.Errorf("doh: CNAME chain too long for %s", host)
}

func (d *dohResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	qname := "_" + service + "._" + proto + "." + name
	dr, err := d.query(ctx, qname, "SRV")
	if err != nil {
		return "", nil, err
	}
	var out []*net.SRV
	for _, a := range dr.answersOfType(dohTypeSRV) {
		fields := strings.SplitN(a.Data, " ", 4)
		if len(fields) != 4 {
			continue
		}
		target := strings.TrimSuffix(fields[3], ".")
		// RFC 2782 §4: target "." means the service is not available.
		if target == "" {
			continue
		}
		var prio, weight, port int
		_, _ = fmt.Sscanf(fields[0], "%d", &prio)
		_, _ = fmt.Sscanf(fields[1], "%d", &weight)
		_, _ = fmt.Sscanf(fields[2], "%d", &port)
		out = append(out, &net.SRV{
			Target:   target,
			Port:     uint16(port),
			Priority: uint16(prio),
			Weight:   uint16(weight),
		})
	}
	return "", out, nil
}

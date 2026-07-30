// Package detect holds signature databases for technology, WAF, CDN,
// service naming, and subdomain-takeover fingerprinting.
package detect

import (
	"regexp"
	"sort"
	"strings"
)

type signature struct {
	name string
	re   *regexp.Regexp
}

func sig(name, pattern string) signature {
	return signature{name, regexp.MustCompile(`(?i)` + pattern)}
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Title extracts and normalizes the <title> of an HTML document.
func Title(html string) string {
	m := titleRe.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	t := strings.Join(strings.Fields(strings.TrimSpace(m[1])), " ")
	// Slice by rune: a byte cut lands mid-codepoint on non-ASCII titles and
	// puts invalid UTF-8 into the JSON/CSV report.
	if r := []rune(t); len(r) > 120 {
		t = string(r[:120])
	}
	return t
}

// Tech matches the header blob + body against the wappalyzer-style DB.
func Tech(headerBlob, body string) []string {
	full := headerBlob + "\n" + body
	set := map[string]struct{}{}
	for _, s := range techSignatures {
		if s.re.MatchString(full) {
			set[s.name] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// WAF matches response headers against the wafw00f-style passive DB.
func WAF(headerBlob string) string {
	for _, s := range wafSignatures {
		if s.re.MatchString(headerBlob) {
			return s.name
		}
	}
	return ""
}

// CDN identifies the CDN from the Server header.
func CDN(server string) string {
	s := strings.ToLower(server)
	for _, c := range cdnSignatures {
		if strings.Contains(s, c.needle) {
			return c.name
		}
	}
	return ""
}

var cdnSignatures = []struct {
	needle, name string
}{
	{"cloudflare", "Cloudflare"},
	{"cloudfront", "CloudFront"},
	{"akamai", "Akamai"},
	{"akamaighost", "Akamai"},
	{"fastly", "Fastly"},
	{"vercel", "Vercel"},
	{"netlify", "Netlify"},
	{"sucuri", "Sucuri"},
}

// ServiceName returns the common service name for a port.
func ServiceName(port int) string { return serviceNames[port] }

// WantsBanner reports whether a port is worth a banner grab.
func WantsBanner(port int) bool { return bannerPorts[port] }

// SignatureCounts returns the size of each signature database.
func SignatureCounts() (tech, waf, takeover int) {
	return len(techSignatures), len(wafSignatures), len(takeoverFingerprints)
}

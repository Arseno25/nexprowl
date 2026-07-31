package scanner

import (
	"fmt"
	"net/http"
	"net/url"
)

// ParseProxyURL validates a proxy URL and returns it parsed.
// Supported schemes: http, https, socks5, socks5h (all handled natively
// by net/http.Transport). Empty input returns nil, nil.
func ParseProxyURL(proxyURL string) (*url.URL, error) {
	if proxyURL == "" {
		return nil, nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("proxy: unsupported scheme %q (want http|https|socks5|socks5h)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy: missing host in %q", proxyURL)
	}
	return u, nil
}

// ApplyProxy routes a transport's traffic through proxyURL.
// Empty proxyURL is a no-op.
func ApplyProxy(t *http.Transport, proxyURL string) error {
	u, err := ParseProxyURL(proxyURL)
	if err != nil || u == nil {
		return err
	}
	t.Proxy = http.ProxyURL(u)
	return nil
}

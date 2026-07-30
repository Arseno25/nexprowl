package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScanContext carries per-target state shared by all modules.
type ScanContext struct {
	Target string
	Opts   *Options
	Result *Result

	emit     Emitter
	resolver *net.Resolver
	limiter  *RateLimiter

	mu          sync.Mutex
	wildcardIPs map[string]bool
}

// NewScanContext normalizes the target and prepares state.
func NewScanContext(rawTarget string, opts *Options, emit Emitter) *ScanContext {
	t, _ := NormalizeTarget(rawTarget)
	return &ScanContext{
		Target: t,
		Opts:   opts,
		Result: &Result{
			Target:   t,
			ScanTime: time.Now().Format(time.RFC3339),
		},
		emit:        emit,
		resolver:    buildResolver(opts),
		limiter:     NewRateLimiter(opts.Rate),
		wildcardIPs: make(map[string]bool),
	}
}

// buildResolver returns the system resolver, or a round-robin resolver
// over custom DNS servers when -r is used (massdns/dnsx technique).
func buildResolver(opts *Options) *net.Resolver {
	if len(opts.Resolvers) == 0 {
		return &net.Resolver{PreferGo: true}
	}
	servers := opts.Resolvers
	var counter uint64
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			i := atomic.AddUint64(&counter, 1)
			server := servers[int(i%uint64(len(servers)))]
			d := net.Dialer{Timeout: opts.Timeout}
			network_ := "udp"
			if strings.HasPrefix(network, "tcp") {
				network_ = "tcp"
			}
			return d.DialContext(ctx, network_, server)
		},
	}
}

// Resolver returns the shared DNS resolver.
func (sc *ScanContext) Resolver() *net.Resolver { return sc.resolver }

// Limit applies the per-target rate limit (no-op when unlimited).
func (sc *ScanContext) Limit(ctx context.Context) { sc.limiter.Wait(ctx) }

// Log emits a log event.
func (sc *ScanContext) Log(level Level, format string, args ...any) {
	if sc.emit != nil {
		sc.emit(Event{
			Type:    EvLog,
			Target:  sc.Target,
			Level:   level,
			Message: fmt.Sprintf(format, args...),
		})
	}
}

// Phase emits a phase-start event.
func (sc *ScanContext) Phase(label string, step, total int) {
	if sc.emit != nil {
		sc.emit(Event{
			Type: EvPhase, Target: sc.Target, Level: LevelInfo,
			Message: label, Step: step, Total: total,
		})
	}
}

// Found emits a finding event (drives UI counters + highlight lines).
func (sc *ScanContext) Found(kind string, format string, args ...any) {
	if sc.emit != nil {
		sc.emit(Event{
			Type:    EvFound,
			Target:  sc.Target,
			Level:   LevelSuccess,
			Kind:    kind,
			Message: fmt.Sprintf(format, args...),
		})
	}
}

// SetError records the first module error.
func (sc *ScanContext) SetError(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	sc.mu.Lock()
	if sc.Result.Error == "" {
		sc.Result.Error = msg
	}
	sc.Result.Errors = append(sc.Result.Errors, msg)
	sc.mu.Unlock()
	sc.Log(LevelError, "%s", msg)
}

// InScope reports whether a discovered host is allowed by the target scope.
func (sc *ScanContext) InScope(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, excluded := range sc.Opts.Exclude {
		if domainMatch(host, excluded) {
			return false
		}
	}
	if domainMatch(host, sc.Target) {
		return true
	}
	for _, included := range sc.Opts.Include {
		if domainMatch(host, included) {
			return true
		}
	}
	return false
}

// NormalizeTarget accepts a hostname, IP, or URL and returns its host.
func NormalizeTarget(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.TrimPrefix(raw, "*.")
	if raw == "" {
		return "", fmt.Errorf("empty target")
	}
	parsed := raw
	if !strings.Contains(raw, "://") {
		parsed = "//" + raw
	}
	u, err := url.Parse(parsed)
	if err != nil {
		return "", fmt.Errorf("invalid target %q", raw)
	}
	host := normalizeHost(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("invalid target %q", raw)
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if len(host) > 253 {
		return "", fmt.Errorf("target hostname too long")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid target hostname %q", host)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return "", fmt.Errorf("invalid target hostname %q", host)
			}
		}
	}
	return host, nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(host, "[]")
}

func domainMatch(host, domain string) bool {
	host, domain = normalizeHost(host), normalizeHost(domain)
	if host == "" || domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// ─── Wildcard DNS handling ────────────────────────────────

// wildcardProbes is how many random names are resolved. One is not enough:
// a wildcard record backed by a rotating pool answers different IPs each
// time, so a single sample filters only part of the noise.
const wildcardProbes = 3

// DetectWildcard resolves several random non-existent subdomains. Zones with
// wildcard DNS make every bruteforce hit a false positive — record the
// wildcard IPs so the subdomain module can filter them out. Safe to call
// more than once; probes accumulate.
func (sc *ScanContext) DetectWildcard(ctx context.Context) {
	found := 0
	for i := 0; i < wildcardProbes; i++ {
		buf := make([]byte, 8)
		_, _ = rand.Read(buf)
		host := hex.EncodeToString(buf) + "." + sc.Target

		c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
		ips, err := sc.resolver.LookupIP(c, "ip", host)
		cancel()
		if err != nil || len(ips) == 0 {
			continue
		}
		sc.mu.Lock()
		for _, ip := range ips {
			sc.wildcardIPs[ip.String()] = true
		}
		found = len(sc.wildcardIPs)
		sc.mu.Unlock()
	}
	if found > 0 {
		sc.Log(LevelWarn, "wildcard DNS detected (%d IPs) — bruteforce results filtered", found)
	}
}

// IsWildcardOnly reports whether every IP belongs to the wildcard set.
func (sc *ScanContext) IsWildcardOnly(ips []string) bool {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if len(sc.wildcardIPs) == 0 || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !sc.wildcardIPs[ip] {
			return false
		}
	}
	return true
}

package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
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
	t := strings.TrimSpace(strings.ToLower(rawTarget))
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimRight(t, "/")
	if i := strings.Index(t, "/"); i >= 0 {
		t = t[:i]
	}
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
func (sc *ScanContext) Phase(label string) {
	if sc.emit != nil {
		sc.emit(Event{Type: EvPhase, Target: sc.Target, Level: LevelInfo, Message: label})
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
	sc.mu.Unlock()
	sc.Log(LevelError, "%s", msg)
}

// ─── Wildcard DNS handling ────────────────────────────────

// DetectWildcard resolves a random non-existent subdomain. Zones with
// wildcard DNS make every bruteforce hit a false positive — record the
// wildcard IPs so the subdomain module can filter them out.
func (sc *ScanContext) DetectWildcard(ctx context.Context) {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	host := hex.EncodeToString(buf) + "." + sc.Target

	c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
	defer cancel()
	ips, err := sc.resolver.LookupIP(c, "ip", host)
	if err != nil || len(ips) == 0 {
		return
	}
	sc.mu.Lock()
	for _, ip := range ips {
		sc.wildcardIPs[ip.String()] = true
	}
	sc.mu.Unlock()
	sc.Log(LevelWarn, "wildcard DNS detected (%d IPs) — bruteforce results filtered", len(ips))
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

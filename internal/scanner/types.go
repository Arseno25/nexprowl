// Package scanner defines the core types, event system, and scan engine.
package scanner

import (
	"fmt"
	"runtime"
	"strings"
	"time"
)

// Build metadata. Overridden at link time by GoReleaser / the Makefile:
//
//	-X github.com/Arseno25/nexprowl/internal/scanner.Version=0.1.0
//	-X github.com/Arseno25/nexprowl/internal/scanner.Commit=<sha>
//	-X github.com/Arseno25/nexprowl/internal/scanner.Date=<RFC3339>
//
// A plain "go build"/"go install" leaves the defaults in place.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// BuildInfo renders the multi-line `nexprowl version` output.
func BuildInfo() string {
	var b strings.Builder
	fmt.Fprintf(&b, "NexProwl %s\n", Version)
	fmt.Fprintf(&b, "  commit:  %s\n", Commit)
	fmt.Fprintf(&b, "  built:   %s\n", Date)
	fmt.Fprintf(&b, "  go:      %s\n", runtime.Version())
	fmt.Fprintf(&b, "  os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return b.String()
}

// Options configures a scan run.
type Options struct {
	Modules     map[string]bool // empty = all
	Workers     int             // worker pool size inside modules
	Concurrency int             // parallel targets
	Timeout     time.Duration
	Ports       []int
	Wordlist    []string
	PassiveOnly bool
	ProbeSubs   bool
	Resolvers   []string // custom DNS servers (host:port); empty = system
	Rate        int      // max network ops/sec per target; 0 = unlimited
	Include     []string
	Exclude     []string
	MaxHosts    int
	ScanAllIPs  bool
	PortsSubs   bool
	ProbeBoth   bool
	Active      bool
	Stealth     bool
	ProxyURL    string // e.g. "socks5://127.0.0.1:9050" or "http://proxy:8080"
	DoH         bool   // DNS-over-HTTPS via Cloudflare
	JitterMs    int    // random delay 0..N ms between requests
	CrawlDepth  int
	CrawlMax    int
	Screenshot  bool
	ChromePath  string
}

// HasModule reports whether a module is enabled.
func (o *Options) HasModule(name string) bool {
	if len(o.Modules) == 0 {
		return true
	}
	return o.Modules[name]
}

// ─── Result model ─────────────────────────────────────────

type Result struct {
	Target       string         `json:"target"`
	ScanTime     string         `json:"scan_time"`
	DurationMs   int64          `json:"duration_ms"`
	Error        string         `json:"error,omitempty"`
	IPs          []string       `json:"ips,omitempty"`
	DNS          *DNSResult     `json:"dns,omitempty"`
	ZoneTransfer []AXFREntry    `json:"zone_transfer,omitempty"`
	Subdomains   []Subdomain    `json:"subdomains,omitempty"`
	Ports        []Port         `json:"ports,omitempty"`
	Web          []WebResult    `json:"web,omitempty"`
	VHosts       []VHost        `json:"vhosts,omitempty"`
	TLS          *TLSResult     `json:"tls,omitempty"`
	TLSHosts     []TLSResult    `json:"tls_hosts,omitempty"`
	Takeovers    []TakeoverHit  `json:"takeovers,omitempty"`
	Endpoints    []Endpoint     `json:"endpoints,omitempty"`
	Sources      []SourceStatus `json:"sources,omitempty"`
	Networks     []NetworkInfo  `json:"networks,omitempty"`
	Errors       []string       `json:"errors,omitempty"`
}

// AXFREntry records a successful zone transfer from one nameserver.
type AXFREntry struct {
	Server  string   `json:"server"`
	Records []string `json:"records"`
}

// VHost is a virtual host discovered via Host-header probing.
type VHost struct {
	Host   string `json:"host"`
	Scheme string `json:"scheme,omitempty"`
	Status int    `json:"status"`
	Size   int64  `json:"size"`
	Title  string `json:"title,omitempty"`
}

type DNSResult struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	CAA   []string `json:"caa,omitempty"`
	SOA   []string `json:"soa,omitempty"`
	SRV   []string `json:"srv,omitempty"`
	PTR   []string `json:"ptr,omitempty"`
	SPF   []string `json:"spf,omitempty"`
	DMARC []string `json:"dmarc,omitempty"`
	CNAME string   `json:"cname,omitempty"`
}

type Subdomain struct {
	Host   string   `json:"host"`
	IPs    []string `json:"ips,omitempty"`
	CNAME  string   `json:"cname,omitempty"`
	Source string   `json:"source"`
}

type Port struct {
	Host    string `json:"host,omitempty"`
	IP      string `json:"ip,omitempty"`
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

type WebResult struct {
	URL          string   `json:"url"`
	Host         string   `json:"host,omitempty"`
	IP           string   `json:"ip,omitempty"`
	Scheme       string   `json:"scheme,omitempty"`
	Port         int      `json:"port,omitempty"`
	Status       int      `json:"status"`
	Title        string   `json:"title,omitempty"`
	Server       string   `json:"server,omitempty"`
	PoweredBy    string   `json:"powered_by,omitempty"`
	Redirect     string   `json:"redirect,omitempty"`
	ContentLen   int64    `json:"content_length,omitempty"`
	ContentType  string   `json:"content_type,omitempty"`
	ResponseMs   int64    `json:"response_ms,omitempty"`
	BodyHash     string   `json:"body_sha256,omitempty"`
	FaviconHash  string   `json:"favicon_sha256,omitempty"`
	Screenshot   string   `json:"screenshot,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	WAF          string   `json:"waf,omitempty"`
	CDN          string   `json:"cdn,omitempty"`
}

type TLSResult struct {
	Host      string   `json:"host,omitempty"`
	Port      int      `json:"port,omitempty"`
	Issuer    string   `json:"issuer,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	ValidFrom string   `json:"valid_from,omitempty"`
	ValidTo   string   `json:"valid_to,omitempty"`
	Version   string   `json:"version,omitempty"`
	Cipher    string   `json:"cipher,omitempty"`
	SANs      []string `json:"sans,omitempty"`
	Expired   bool     `json:"expired,omitempty"`
	Mismatch  bool     `json:"hostname_mismatch,omitempty"`
	DaysLeft  int      `json:"days_left,omitempty"`
}

type Endpoint struct {
	URL    string `json:"url"`
	Source string `json:"source,omitempty"`
	Depth  int    `json:"depth,omitempty"`
}

type SourceStatus struct {
	Name       string `json:"name"`
	Found      int    `json:"found"`
	DurationMs int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

type NetworkInfo struct {
	IP     string `json:"ip"`
	ASN    string `json:"asn,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Owner  string `json:"owner,omitempty"`
}

type TakeoverHit struct {
	Host    string `json:"host"`
	CNAME   string `json:"cname"`
	Service string `json:"service"`
	Note    string `json:"note"`
}

// ─── Event system (engine → UI) ───────────────────────────

type Level string

const (
	LevelInfo    Level = "info"
	LevelSuccess Level = "ok"
	LevelWarn    Level = "warn"
	LevelError   Level = "err"
)

type EventType int

const (
	EvLog        EventType = iota // generic log line
	EvPhase                       // module phase started, Message = phase label
	EvFound                       // notable finding; Kind = sub|port|live|takeover
	EvTargetDone                  // target finished
)

type Event struct {
	Type    EventType
	Target  string
	Level   Level
	Kind    string // finding kind for EvFound
	Message string
	Step    int // current module step for EvPhase
	Total   int // total active module steps for EvPhase
}

// Emitter receives scan events. May be nil (silent mode).
type Emitter func(Event)

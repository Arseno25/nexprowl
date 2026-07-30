// Package scanner defines the core types, event system, and scan engine.
package scanner

import "time"

// Version of the tool.
const Version = "1.0.0"

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
	Resolvers   []string        // custom DNS servers (host:port); empty = system
	Rate        int             // max network ops/sec per target; 0 = unlimited
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
	Target       string        `json:"target"`
	ScanTime     string        `json:"scan_time"`
	DurationMs   int64         `json:"duration_ms"`
	Error        string        `json:"error,omitempty"`
	IPs          []string      `json:"ips,omitempty"`
	DNS          *DNSResult    `json:"dns,omitempty"`
	ZoneTransfer []AXFREntry   `json:"zone_transfer,omitempty"`
	Subdomains   []Subdomain   `json:"subdomains,omitempty"`
	Ports        []Port        `json:"ports,omitempty"`
	Web          []WebResult   `json:"web,omitempty"`
	VHosts       []VHost       `json:"vhosts,omitempty"`
	TLS          *TLSResult    `json:"tls,omitempty"`
	Takeovers    []TakeoverHit `json:"takeovers,omitempty"`
}

// AXFREntry records a successful zone transfer from one nameserver.
type AXFREntry struct {
	Server  string   `json:"server"`
	Records []string `json:"records"`
}

// VHost is a virtual host discovered via Host-header probing.
type VHost struct {
	Host   string `json:"host"`
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
	CNAME string   `json:"cname,omitempty"`
}

type Subdomain struct {
	Host   string   `json:"host"`
	IPs    []string `json:"ips,omitempty"`
	CNAME  string   `json:"cname,omitempty"`
	Source string   `json:"source"`
}

type Port struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

type WebResult struct {
	URL          string   `json:"url"`
	Status       int      `json:"status"`
	Title        string   `json:"title,omitempty"`
	Server       string   `json:"server,omitempty"`
	PoweredBy    string   `json:"powered_by,omitempty"`
	Redirect     string   `json:"redirect,omitempty"`
	ContentLen   int64    `json:"content_length,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	WAF          string   `json:"waf,omitempty"`
	CDN          string   `json:"cdn,omitempty"`
}

type TLSResult struct {
	Issuer    string   `json:"issuer,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	ValidFrom string   `json:"valid_from,omitempty"`
	ValidTo   string   `json:"valid_to,omitempty"`
	Version   string   `json:"version,omitempty"`
	Cipher    string   `json:"cipher,omitempty"`
	SANs      []string `json:"sans,omitempty"`
	Expired   bool     `json:"expired,omitempty"`
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
}

// Emitter receives scan events. May be nil (silent mode).
type Emitter func(Event)

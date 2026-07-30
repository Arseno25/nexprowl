package modules

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"dscan/internal/detect"
	"dscan/internal/scanner"
)

// Ports is a rustscan-style TCP connect scanner: large worker pool,
// short timeout, banner grabbing on text protocols.
type Ports struct{}

func (Ports) Name() string { return "ports" }

func (Ports) Run(ctx context.Context, sc *scanner.ScanContext) error {
	host := sc.Target
	if len(sc.Result.IPs) > 0 {
		host = sc.Result.IPs[0] // skip re-resolving per port
	}

	jobs := make(chan int, sc.Opts.Workers)
	results := make(chan scanner.Port, len(sc.Opts.Ports))
	var wg sync.WaitGroup
	dialer := &net.Dialer{Timeout: sc.Opts.Timeout}

	worker := func() {
		defer wg.Done()
		for port := range jobs {
			sc.Limit(ctx)
			c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
			conn, err := dialer.DialContext(c, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
			cancel()
			if err != nil {
				continue
			}
			p := scanner.Port{Port: port, Service: detect.ServiceName(port)}
			if detect.WantsBanner(port) {
				p.Banner = grabBanner(conn)
			}
			_ = conn.Close()
			results <- p
		}
	}

	for i := 0; i < min(sc.Opts.Workers, len(sc.Opts.Ports)); i++ {
		wg.Add(1)
		go worker()
	}
portLoop:
	for _, p := range sc.Opts.Ports {
		select {
		case jobs <- p:
		case <-ctx.Done():
			break portLoop
		}
	}
	close(jobs)
	wg.Wait()
	close(results)

	for p := range results {
		sc.Result.Ports = append(sc.Result.Ports, p)
	}
	sort.Slice(sc.Result.Ports, func(i, j int) bool {
		return sc.Result.Ports[i].Port < sc.Result.Ports[j].Port
	})

	for _, p := range sc.Result.Ports {
		if p.Banner != "" {
			sc.Found("port", "%d/tcp %-12s %s", p.Port, p.Service, p.Banner)
		} else {
			sc.Found("port", "%d/tcp %s", p.Port, p.Service)
		}
	}
	sc.Log(scanner.LevelSuccess, "%d open ports", len(sc.Result.Ports))
	return nil
}

// grabBanner reads the greeting banner of text protocols (nmap-lite).
func grabBanner(conn net.Conn) string {
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	var b strings.Builder
	for _, r := range strings.TrimSpace(string(buf[:n])) {
		if r == '\n' || r == '\r' {
			break
		}
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

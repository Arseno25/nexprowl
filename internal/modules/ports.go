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

type portTarget struct {
	host string
	ip   string
}

type portJob struct {
	target portTarget
	port   int
}

func (Ports) Run(ctx context.Context, sc *scanner.ScanContext) error {
	var targets []portTarget
	addTarget := func(host string, ips []string) {
		if len(ips) == 0 {
			targets = append(targets, portTarget{host: host})
			return
		}
		if !sc.Opts.ScanAllIPs {
			ips = ips[:1]
		}
		for _, ip := range ips {
			targets = append(targets, portTarget{host: host, ip: ip})
		}
	}
	mainIPs := append([]string{}, sc.Result.IPs...)
	if sc.Result.DNS != nil {
		mainIPs = append(mainIPs, sc.Result.DNS.AAAA...)
	}
	addTarget(sc.Target, mainIPs)
	if sc.Opts.PortsSubs {
		for _, sub := range sc.Result.Subdomains {
			addTarget(sub.Host, sub.IPs)
		}
	}

	jobs := make(chan portJob, sc.Opts.Workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []scanner.Port
	dialer := &net.Dialer{Timeout: sc.Opts.Timeout}

	worker := func() {
		defer wg.Done()
		for job := range jobs {
			address := job.target.ip
			if address == "" {
				address = job.target.host
			}
			sc.Limit(ctx)
			c, cancel := context.WithTimeout(ctx, sc.Opts.Timeout)
			conn, err := dialer.DialContext(c, "tcp", net.JoinHostPort(address, fmt.Sprint(job.port)))
			cancel()
			if err != nil {
				continue
			}
			p := scanner.Port{
				Host: job.target.host, IP: job.target.ip, Port: job.port,
				Service: detect.ServiceName(job.port),
			}
			if detect.WantsBanner(job.port) {
				p.Banner = grabBanner(conn)
			}
			_ = conn.Close()
			mu.Lock()
			results = append(results, p)
			mu.Unlock()
		}
	}

	workCount := len(targets) * len(sc.Opts.Ports)
	for i := 0; i < min(sc.Opts.Workers, workCount); i++ {
		wg.Add(1)
		go worker()
	}
portLoop:
	for _, target := range targets {
		for _, p := range sc.Opts.Ports {
			select {
			case jobs <- portJob{target: target, port: p}:
			case <-ctx.Done():
				break portLoop
			}
		}
	}
	close(jobs)
	wg.Wait()
	sc.Result.Ports = results
	sort.Slice(sc.Result.Ports, func(i, j int) bool {
		if sc.Result.Ports[i].Host != sc.Result.Ports[j].Host {
			return sc.Result.Ports[i].Host < sc.Result.Ports[j].Host
		}
		if sc.Result.Ports[i].IP != sc.Result.Ports[j].IP {
			return sc.Result.Ports[i].IP < sc.Result.Ports[j].IP
		}
		return sc.Result.Ports[i].Port < sc.Result.Ports[j].Port
	})

	for _, p := range sc.Result.Ports {
		if p.Banner != "" {
			sc.Found("port", "%s:%d/tcp %-12s %s", p.Host, p.Port, p.Service, p.Banner)
		} else {
			sc.Found("port", "%s:%d/tcp %s", p.Host, p.Port, p.Service)
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

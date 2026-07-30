// Package data provides embedded wordlists and port specifications.
package data

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"
)

//go:embed subdomains.txt
var subdomainList string

// Subdomains returns the built-in bruteforce wordlist.
func Subdomains() []string {
	var out []string
	for _, line := range strings.Split(subdomainList, "\n") {
		w := strings.TrimSpace(line)
		if w != "" && !strings.HasPrefix(w, "#") {
			out = append(out, w)
		}
	}
	return out
}

// TopPorts — the ~65 most valuable ports for recon.
var TopPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095,
	2096, 2222, 2375, 2376, 3128, 3306, 3389, 3690, 4333, 4444,
	4489, 4848, 5000, 5432, 5555, 5631, 5800, 5900, 5901, 5984,
	5985, 5986, 6379, 6646, 7001, 7002, 8080, 8081, 8443, 8888,
	9000, 9001, 9042, 9090, 9100, 9200, 9300, 9418, 9999, 10000,
	11211, 27017, 27018, 50030, 50060, 50070,
}

// ParsePorts handles "top100", "full", "80,443,8080", "1-1024".
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	switch spec {
	case "", "top100":
		return append([]int(nil), TopPorts...), nil
	case "full", "all":
		ports := make([]int, 0, 65535)
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		return ports, nil
	}

	var ports []int
	seen := map[int]struct{}{}
	add := func(p int) error {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d out of range", p)
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			ports = append(ports, p)
		}
		return nil
	}

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			loN, err1 := strconv.Atoi(strings.TrimSpace(lo))
			hiN, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || loN > hiN {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for p := loN; p <= hiN; p++ {
				if err := add(p); err != nil {
					return nil, err
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		if err := add(p); err != nil {
			return nil, err
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports in %q", spec)
	}
	return ports, nil
}

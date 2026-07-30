// Package modules implements the scan capabilities of dscan.
package modules

import "dscan/internal/scanner"

// All returns every module in execution order.
// Order matters: dns feeds subdomain filtering + ports; sub feeds http/takeover;
// vhost needs IPs from dns; takeover needs CNAMEs from sub.
func All() []scanner.Module {
	return []scanner.Module{
		DNS{},
		TLSSeed{},
		Subdomain{},
		Ports{},
		VHost{},
		HTTP{},
		Crawl{},
		TLS{},
		Takeover{},
	}
}

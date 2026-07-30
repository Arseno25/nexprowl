package modules

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"dscan/internal/scanner"
)

func TestPortHTTPAndCrawlPipeline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			_, _ = w.Write([]byte("icon"))
			return
		}
		_, _ = fmt.Fprint(w, `<html><title>Local test</title><a href="/api?q=1">API</a></html>`)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)

	opts := &scanner.Options{
		Workers: 4, Timeout: 300 * time.Millisecond, Ports: []int{port},
		CrawlDepth: 1, CrawlMax: 20, MaxHosts: 100,
	}
	sc := scanner.NewScanContext(host, opts, nil)
	sc.Result.IPs = []string{host}
	if err := (Ports{}).Run(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	if len(sc.Result.Ports) != 1 || sc.Result.Ports[0].Port != port {
		t.Fatalf("ports = %#v", sc.Result.Ports)
	}
	if err := (HTTP{}).Run(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	foundWeb := false
	for _, web := range sc.Result.Web {
		if web.Port == port && web.BodyHash != "" && web.ResponseMs >= 0 {
			foundWeb = true
		}
	}
	if !foundWeb {
		t.Fatalf("web = %#v", sc.Result.Web)
	}
	if err := (Crawl{}).Run(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	foundAPI := false
	for _, endpoint := range sc.Result.Endpoints {
		foundAPI = foundAPI || strings.Contains(endpoint.URL, "/api?q=1")
	}
	if !foundAPI {
		t.Fatalf("crawler endpoints = %#v", sc.Result.Endpoints)
	}
}

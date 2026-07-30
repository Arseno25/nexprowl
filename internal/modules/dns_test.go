package modules

import (
	"context"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
	"time"

	"nexprowl/internal/scanner"
)

func TestDNSQueryAndMessageParsing(t *testing.T) {
	query := buildDNSQuery("example.com", dnsTypeA, 0x1234)
	if binary.BigEndian.Uint16(query[:2]) != 0x1234 ||
		binary.BigEndian.Uint16(query[4:6]) != 1 {
		t.Fatalf("invalid query header: %x", query[:12])
	}

	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	answer := []byte{
		0xc0, 0x0c, // answer name points to question
		0x00, 0x01, // A
		0x00, 0x01, // IN
		0x00, 0x00, 0x00, 0x3c, // TTL
		0x00, 0x04,
		192, 0, 2, 10,
	}
	response = append(response, answer...)
	lines, hosts, err := parseDNSMessage(response)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := lines, []string{"example.com A 192.0.2.10"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("records = %v, want %v", got, want)
	}
	if got, want := hosts, []string{"example.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("hosts = %v, want %v", got, want)
	}
	if _, _, err := parseDNSMessage([]byte{1, 2, 3}); err == nil {
		t.Fatal("short DNS message was accepted")
	}
}

func TestAXFRHostsToSubdomains(t *testing.T) {
	got := axfrHostsToSubdomains("example.com", []string{
		"EXAMPLE.com.",
		"api.example.com.",
		"api.example.com",
		"nested.api.example.com.",
		"outside.test.",
		"",
	})
	if len(got) != 2 || got[0].Source != "axfr" {
		t.Fatalf("subdomains = %#v", got)
	}
	joined := got[0].Host + "," + got[1].Host
	if !strings.Contains(joined, "api.example.com") ||
		!strings.Contains(joined, "nested.api.example.com") {
		t.Fatalf("subdomains = %#v", got)
	}
}

func TestDNSModuleNamesAndRegistry(t *testing.T) {
	want := []string{"dns", "tls", "sub", "ports", "vhost", "http", "crawl", "tls", "takeover"}
	all := All()
	if len(all) != len(want) {
		t.Fatalf("All returned %d modules, want %d", len(all), len(want))
	}
	for i, module := range all {
		if module.Name() != want[i] {
			t.Errorf("module %d = %q, want %q", i, module.Name(), want[i])
		}
	}
}

func TestDNSRunLocalhost(t *testing.T) {
	sc := scanner.NewScanContext("localhost", &scanner.Options{
		Workers: 2, Timeout: 100 * time.Millisecond,
	}, nil)
	if err := (DNS{}).Run(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	if sc.Result.DNS == nil {
		t.Fatal("DNS result was not initialized")
	}
	if got := lookupASN(t.Context(), sc, "not-an-ip"); got != nil {
		t.Fatalf("invalid ASN lookup = %#v", got)
	}
}

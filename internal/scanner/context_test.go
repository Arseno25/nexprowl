package scanner

import (
	"context"
	"encoding/binary"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestNormalizeTarget(t *testing.T) {
	for raw, want := range map[string]string{
		"Example.COM":                   "example.com",
		"https://sub.example.com/a?q=1": "sub.example.com",
		"http://127.0.0.1:8080/path":    "127.0.0.1",
		"*.example.com.":                "example.com",
	} {
		got, err := NormalizeTarget(raw)
		if err != nil || got != want {
			t.Errorf("NormalizeTarget(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"", "bad host", "-bad.example"} {
		if _, err := NormalizeTarget(raw); err == nil {
			t.Errorf("NormalizeTarget(%q) accepted invalid input", raw)
		}
	}
}

func TestScope(t *testing.T) {
	sc := NewScanContext("example.com", &Options{
		Include: []string{"extra.test"},
		Exclude: []string{"admin.example.com"},
	}, nil)
	got := []bool{
		sc.InScope("www.example.com"),
		sc.InScope("admin.example.com"),
		sc.InScope("x.extra.test"),
		sc.InScope("example.net"),
	}
	if want := []bool{true, false, true, false}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scope = %v, want %v", got, want)
	}
}

func TestContextEventsAndWildcardFiltering(t *testing.T) {
	var events []Event
	sc := NewScanContext("example.com", &Options{Timeout: time.Second}, func(event Event) {
		events = append(events, event)
	})
	if sc.Resolver() == nil {
		t.Fatal("resolver was not initialized")
	}
	sc.Limit(context.Background())
	sc.Log(LevelInfo, "hello %s", "world")
	sc.Found("sub", "%s", "api.example.com")
	sc.Phase("dns", 1, 2)
	if len(events) != 3 || events[0].Message != "hello world" ||
		events[1].Kind != "sub" || events[2].Step != 1 {
		t.Fatalf("events = %#v", events)
	}

	sc.wildcardIPs["192.0.2.1"] = true
	if !sc.IsWildcardOnly([]string{"192.0.2.1"}) {
		t.Error("wildcard-only address was not recognized")
	}
	if sc.IsWildcardOnly([]string{"192.0.2.1", "192.0.2.2"}) ||
		sc.IsWildcardOnly(nil) {
		t.Error("mixed or empty addresses were classified as wildcard-only")
	}
}

func TestNormalizeTargetEdgeCases(t *testing.T) {
	valid := map[string]string{
		"[2001:db8::1]:443": "2001:db8::1",
		"foo_bar.example":   "foo_bar.example",
	}
	for raw, want := range valid {
		got, err := NormalizeTarget(raw)
		if err != nil || got != want {
			t.Errorf("NormalizeTarget(%q) = %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{
		"bad-.example",
		"bad!.example",
		"a..example",
		string(make([]byte, 254)),
	} {
		if _, err := NormalizeTarget(raw); err == nil {
			t.Errorf("NormalizeTarget(%q) succeeded", raw)
		}
	}
}

func TestDetectWildcardWithCustomResolver(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go serveWildcardDNS(conn)

	var events []Event
	sc := NewScanContext("example.test", &Options{
		Timeout: 500 * time.Millisecond,
		Resolvers: []string{
			conn.LocalAddr().String(),
		},
	}, func(event Event) {
		events = append(events, event)
	})
	sc.DetectWildcard(t.Context())
	if !sc.IsWildcardOnly([]string{"192.0.2.55"}) {
		t.Fatalf("wildcard IPs = %#v", sc.wildcardIPs)
	}
	foundWarning := false
	for _, event := range events {
		foundWarning = foundWarning || event.Level == LevelWarn
	}
	if !foundWarning {
		t.Fatalf("events = %#v", events)
	}
}

func TestJitterSleep(t *testing.T) {
	// maxMs <= 0 must return immediately.
	start := time.Now()
	jitterSleep(t.Context(), 0)
	if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
		t.Fatalf("jitterSleep(0) took %s; want immediate", elapsed)
	}

	// A positive bound sleeps at most maxMs (plus scheduler slack).
	start = time.Now()
	jitterSleep(t.Context(), 50)
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("jitterSleep(50) took %s; want <= ~50ms", elapsed)
	}

	// A cancelled context returns immediately instead of sleeping.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	start = time.Now()
	jitterSleep(ctx, 60_000) // would sleep up to a minute without the cancel check
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("jitterSleep(cancelled) took %s; want immediate", elapsed)
	}
}

// TestJitterSleepConcurrent pins the race that a shared rand.Source had:
// Limit() is called from every module worker goroutine, so the jitter
// path must be safe under the race detector.
func TestJitterSleepConcurrent(t *testing.T) {
	sc := NewScanContext("example.com", &Options{JitterMs: 2}, nil)
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				sc.Limit(t.Context())
			}
		}()
	}
	wg.Wait()
}

func serveWildcardDNS(conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		offset := 12
		for offset < len(query) && query[offset] != 0 {
			offset += int(query[offset]) + 1
		}
		if offset+5 > len(query) {
			continue
		}
		questionEnd := offset + 5
		qtype := binary.BigEndian.Uint16(query[offset+1 : offset+3])
		response := append([]byte(nil), query[:questionEnd]...)
		binary.BigEndian.PutUint16(response[2:4], 0x8180)
		binary.BigEndian.PutUint16(response[6:8], 1)
		binary.BigEndian.PutUint16(response[8:10], 0)
		binary.BigEndian.PutUint16(response[10:12], 0)
		answer := []byte{0xc0, 0x0c, byte(qtype >> 8), byte(qtype), 0, 1, 0, 0, 0, 30}
		switch qtype {
		case 1:
			answer = append(answer, 0, 4, 192, 0, 2, 55)
		case 28:
			answer = append(answer, 0, 16)
			answer = append(answer, net.ParseIP("2001:db8::55").To16()...)
		default:
			binary.BigEndian.PutUint16(response[6:8], 0)
		}
		response = append(response, answer...)
		_, _ = conn.WriteTo(response, addr)
	}
}

package data

import "testing"

func TestParsePorts(t *testing.T) {
	ok := []struct {
		spec  string
		first int
		count int
	}{
		{"top100", 21, len(TopPorts)},
		{"", 21, len(TopPorts)},
		{"full", 1, 65535},
		{"80,443", 80, 2},
		{"1-1024", 1, 1024},
		{"80,80,443", 80, 2},  // deduped
		{" 80 , 443 ", 80, 2}, // whitespace tolerated
		{"8080,1-3", 8080, 4}, // mixed list and range
		{"443-443", 443, 1},   // single-value range
	}
	for _, c := range ok {
		got, err := ParsePorts(c.spec)
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.spec, err)
			continue
		}
		if len(got) != c.count {
			t.Errorf("%q: got %d ports, want %d", c.spec, len(got), c.count)
		}
		if len(got) > 0 && got[0] != c.first {
			t.Errorf("%q: first port %d, want %d", c.spec, got[0], c.first)
		}
	}

	bad := []string{"0", "65536", "1-70000", "abc", "10-1", "-", ","}
	for _, spec := range bad {
		if got, err := ParsePorts(spec); err == nil {
			t.Errorf("%q: want error, got %v", spec, got)
		}
	}
}

// TestParsePortsIsolated guards the top100 case against callers mutating the
// returned slice, which used to be shared package state.
func TestParsePortsIsolated(t *testing.T) {
	a, _ := ParsePorts("top100")
	a[0] = -1
	b, _ := ParsePorts("top100")
	if b[0] != TopPorts[0] {
		t.Fatalf("ParsePorts aliases TopPorts: got %d, want %d", b[0], TopPorts[0])
	}
}

func TestSubdomains(t *testing.T) {
	wl := Subdomains()
	if len(wl) < 100 {
		t.Fatalf("embedded wordlist has %d entries, want >= 100", len(wl))
	}
	for _, w := range wl {
		if w == "" || w[0] == '#' {
			t.Fatalf("wordlist contains a blank or comment entry: %q", w)
		}
	}
}

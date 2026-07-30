package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestReorderArgs(t *testing.T) {
	cases := []struct {
		in, want []string
	}{
		// positionals moved behind flags, both orders equivalent
		{[]string{"-t", "200", "example.com"}, []string{"-t", "200", "example.com"}},
		{[]string{"example.com", "-t", "200"}, []string{"-t", "200", "example.com"}},
		// bool flags must not swallow the following positional
		{[]string{"example.com", "-silent"}, []string{"-silent", "example.com"}},
		{[]string{"-passive", "a.com", "b.com"}, []string{"-passive", "a.com", "b.com"}},
		// -flag=value form keeps its value attached
		{[]string{"a.com", "-t=50"}, []string{"-t=50", "a.com"}},
		// value flag at the very end has no value to take
		{[]string{"a.com", "-o"}, []string{"-o", "a.com"}},
		{nil, nil},
	}
	for _, c := range cases {
		if got := reorderArgs(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("reorderArgs(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestLoadReader(t *testing.T) {
	got, err := LoadReader(strings.NewReader(" example.com \n# comment\nexample.com\napi.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LoadReader = %v, want %v", got, want)
	}
}

// TestAtLeast pins the clamp that keeps a zero pool size from hanging every
// module on an unbuffered job channel.
func TestAtLeast(t *testing.T) {
	for _, c := range []struct{ v, floor, want int }{
		{0, 1, 1}, {-5, 1, 1}, {1, 1, 1}, {300, 1, 300},
	} {
		if got := atLeast(c.v, c.floor); got != c.want {
			t.Errorf("atLeast(%d, %d) = %d, want %d", c.v, c.floor, got, c.want)
		}
	}
}

func TestNormalizeResolvers(t *testing.T) {
	got := normalizeResolvers([]string{"1.1.1.1", " 8.8.8.8:5353 ", "", "  "})
	want := []string{"1.1.1.1:53", "8.8.8.8:5353"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalizeResolvers = %v, want %v", got, want)
	}
}

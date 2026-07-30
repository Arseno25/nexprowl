package scanner

import (
	"reflect"
	"testing"
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

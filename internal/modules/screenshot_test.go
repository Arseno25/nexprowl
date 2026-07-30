package modules

import "testing"

func TestScreenshotName(t *testing.T) {
	a := screenshotName("https://example.com")
	b := screenshotName("https://example.com")
	c := screenshotName("https://example.com/login")
	if a != b || a == c || len(a) != 28 {
		t.Fatalf("unexpected screenshot names: %q %q %q", a, b, c)
	}
}

package modules

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nexprowl/internal/scanner"
)

func TestScreenshotName(t *testing.T) {
	a := screenshotName("https://example.com")
	b := screenshotName("https://example.com")
	c := screenshotName("https://example.com/login")
	if a != b || a == c || len(a) != 28 {
		t.Fatalf("unexpected screenshot names: %q %q %q", a, b, c)
	}
}

func TestFindChromeAndWaitForFile(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "chrome")
	if err := os.WriteFile(executable, []byte("fake"), 0700); err != nil {
		t.Fatal(err)
	}
	got, err := findChrome(executable)
	if err != nil || got != executable {
		t.Fatalf("findChrome = %q, %v", got, err)
	}
	if _, err := findChrome(t.TempDir()); err == nil {
		t.Fatal("directory accepted as Chrome executable")
	}
	if _, err := findChrome(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing Chrome executable accepted")
	}

	file := filepath.Join(t.TempDir(), "shot.png")
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = os.WriteFile(file, []byte("png"), 0600)
	}()
	if !waitForFile(context.Background(), file, time.Second) {
		t.Fatal("created file was not detected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitForFile(ctx, filepath.Join(t.TempDir(), "never"), time.Second) {
		t.Fatal("cancelled wait succeeded")
	}
}

func TestCaptureScreenshotsEmptyResults(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "chrome")
	if err := os.WriteFile(executable, []byte("fake"), 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "screenshots")
	if err := CaptureScreenshots(t.Context(), dir, []*scanner.Result{{Target: "example.com"}}, executable); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Fatalf("screenshot directory: %v", err)
	}
	results := []*scanner.Result{{
		Target: "example.com",
		Web:    []scanner.WebResult{{URL: "https://example.com"}},
	}}
	if err := CaptureScreenshots(t.Context(), dir, results, executable); err == nil {
		t.Fatal("invalid browser executable did not fail")
	}
	if results[0].Web[0].Screenshot != "" {
		t.Fatal("failed screenshot was recorded")
	}
}

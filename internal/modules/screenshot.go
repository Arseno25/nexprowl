package modules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/Arseno25/nexprowl/internal/scanner"
)

// CaptureScreenshots uses an installed Chrome/Chromium executable so the
// core scanner remains a small dependency-free binary.
func CaptureScreenshots(ctx context.Context, dir string, results []*scanner.Result, configuredChrome string) error {
	chrome, err := findChrome(configuredChrome)
	if err != nil {
		return err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	sem := make(chan struct{}, 1)
	var wg sync.WaitGroup
	var firstErr error
	var mu sync.Mutex
	for _, result := range results {
		for i := range result.Web {
			web := &result.Web[i]
			// Take the slot before spawning: a scan with hundreds of live
			// hosts would otherwise park one goroutine per host on a
			// semaphore that only ever admits one at a time.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Wait()
				return firstErr
			}

			wg.Add(1)
			go func(web *scanner.WebResult) {
				defer wg.Done()
				defer func() { <-sem }()

				name := screenshotName(web.URL)
				path := filepath.Join(dir, name)
				profileDir := filepath.Join(os.TempDir(), "nexprowl-chrome-"+name[:24])
				if err := os.MkdirAll(profileDir, 0700); err != nil {
					return
				}
				defer os.RemoveAll(profileDir)
				c, cancel := context.WithTimeout(ctx, 25*time.Second)
				defer cancel()
				cmd := exec.CommandContext(c, chrome,
					"--headless=new",
					"--disable-gpu",
					"--disable-extensions",
					"--hide-scrollbars",
					"--ignore-certificate-errors",
					"--no-first-run",
					"--user-data-dir="+profileDir,
					"--window-size=1440,900",
					"--screenshot="+path,
					web.URL,
				)
				if err := cmd.Run(); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("%s: %v", web.URL, err)
					}
					mu.Unlock()
					return
				}
				if !waitForFile(ctx, path, 15*time.Second) {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("%s: Chrome returned without creating a screenshot", web.URL)
					}
					mu.Unlock()
					return
				}
				web.Screenshot = filepath.ToSlash(filepath.Join("screenshots", name))
			}(web)
		}
	}
	wg.Wait()
	return firstErr
}

func waitForFile(ctx context.Context, path string, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		case <-ticker.C:
		}
	}
}

func screenshotName(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return hex.EncodeToString(sum[:12]) + ".png"
}

func findChrome(configured string) (string, error) {
	if configured != "" {
		if info, err := os.Stat(configured); err == nil && !info.IsDir() {
			return configured, nil
		}
		return "", fmt.Errorf("chrome executable not found: %s", configured)
	}
	for _, name := range []string{"chrome", "google-chrome", "chromium", "chromium-browser", "msedge"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	if runtime.GOOS == "windows" {
		for _, path := range []string{
			filepath.Join(os.Getenv("ProgramFiles"), "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(os.Getenv("LocalAppData"), "Google", "Chrome", "Application", "chrome.exe"),
		} {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("Chrome/Chromium not found; use -chrome PATH")
}

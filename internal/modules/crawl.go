package modules

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Arseno25/nexprowl/internal/scanner"
)

// Crawl performs a bounded, same-scope crawl over live web services.
type Crawl struct{}

func (Crawl) Name() string { return "crawl" }

type crawlItem struct {
	url    string
	source string
	depth  int
}

var (
	// ponytail: regex extraction covers static markup and common JS strings;
	// replace with a real browser parser only when SPA coverage justifies it.
	linkRe   = regexp.MustCompile(`(?is)(?:href|src|action)\s*=\s*["']([^"'#]+)["']`)
	jsURLRe  = regexp.MustCompile(`(?i)["']((?:https?://|/)[^"' <>{}\\]{2,})["']`)
	xmlLocRe = regexp.MustCompile(`(?is)<loc>\s*([^<\s]+)\s*</loc>`)
	robotsRe = regexp.MustCompile(`(?im)^(?:allow|disallow|sitemap):\s*(\S+)`)
)

var skippedExtensions = map[string]bool{
	".7z": true, ".avi": true, ".bmp": true, ".css": true, ".eot": true,
	".gif": true, ".gz": true, ".ico": true, ".jpeg": true, ".jpg": true,
	".mov": true, ".mp3": true, ".mp4": true, ".pdf": true, ".png": true,
	".rar": true, ".svg": true, ".tar": true, ".ttf": true, ".webp": true,
	".woff": true, ".woff2": true, ".zip": true,
}

func (Crawl) Run(ctx context.Context, sc *scanner.ScanContext) error {
	if sc.Opts.CrawlDepth <= 0 || sc.Opts.CrawlMax <= 0 || len(sc.Result.Web) == 0 {
		return nil
	}
	client := newScopedHTTPClient(sc)
	seen := map[string]bool{}
	var queue []crawlItem
	for _, web := range sc.Result.Web {
		queue = append(queue, crawlItem{url: web.URL, source: "http", depth: 0})
	}

	// Known discovery files are cheap and frequently reveal hidden routes.
	for _, web := range sc.Result.Web {
		base, err := url.Parse(web.URL)
		if err != nil {
			continue
		}
		for _, path := range []string{"/robots.txt", "/sitemap.xml"} {
			u := *base
			u.Path, u.RawQuery, u.Fragment = path, "", ""
			queue = append(queue, crawlItem{url: u.String(), source: strings.TrimPrefix(path, "/"), depth: 0})
		}
	}

	for len(queue) > 0 && len(seen) < sc.Opts.CrawlMax {
		item := queue[0]
		queue = queue[1:]
		normalized, ok := normalizeCrawlURL(item.url, nil, sc)
		if !ok || seen[normalized] {
			continue
		}
		seen[normalized] = true
		sc.Result.Endpoints = append(sc.Result.Endpoints, scanner.Endpoint{
			URL: normalized, Source: item.source, Depth: item.depth,
		})
		if item.depth >= sc.Opts.CrawlDepth {
			continue
		}

		sc.Limit(ctx)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalized, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 NexProwl/"+scanner.Version)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if len(body) == 0 {
			continue
		}
		base := resp.Request.URL
		text := string(body)
		for _, match := range linkRe.FindAllStringSubmatch(text, -1) {
			if next, ok := normalizeCrawlURL(match[1], base, sc); ok && !seen[next] {
				queue = append(queue, crawlItem{url: next, source: "html", depth: item.depth + 1})
			}
		}
		for _, match := range jsURLRe.FindAllStringSubmatch(text, -1) {
			if next, ok := normalizeCrawlURL(match[1], base, sc); ok && !seen[next] {
				queue = append(queue, crawlItem{url: next, source: "javascript", depth: item.depth + 1})
			}
		}
		for _, re := range []*regexp.Regexp{xmlLocRe, robotsRe} {
			for _, match := range re.FindAllStringSubmatch(text, -1) {
				if next, ok := normalizeCrawlURL(match[1], base, sc); ok && !seen[next] {
					queue = append(queue, crawlItem{url: next, source: item.source, depth: item.depth + 1})
				}
			}
		}
	}

	sort.Slice(sc.Result.Endpoints, func(i, j int) bool {
		return sc.Result.Endpoints[i].URL < sc.Result.Endpoints[j].URL
	})
	sc.Log(scanner.LevelSuccess, "%d scoped endpoints discovered", len(sc.Result.Endpoints))
	return nil
}

func normalizeCrawlURL(raw string, base *url.URL, sc *scanner.ScanContext) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "javascript:") ||
		strings.HasPrefix(raw, "data:") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if !sc.InScope(u.Hostname()) || skippedExtensions[strings.ToLower(pathExtension(u.Path))] {
		return "", false
	}
	u.Fragment = ""
	return u.String(), true
}

func pathExtension(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		ext := path[i:]
		if j := strings.IndexAny(ext, "/?"); j >= 0 {
			ext = ext[:j]
		}
		return ext
	}
	return ""
}

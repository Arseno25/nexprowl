package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// webhookClient is deliberately not http.DefaultClient: the payload contains
// the full scan summary, and DefaultClient follows redirects without limit,
// so a 307/308 chain could replay that body to a host the user never named.
var webhookClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       10 * time.Second,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// NotifyWebhook POSTs payload as JSON to endpoint. An empty endpoint is a
// no-op. Only http and https endpoints are accepted.
func NotifyWebhook(ctx context.Context, endpoint string, payload any) error {
	if endpoint == "" {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("webhook: invalid URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return fmt.Errorf("webhook: unsupported scheme %q (use http or https)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("webhook: URL has no host")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := webhookClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("webhook status %d: %s", resp.StatusCode, msg)
	}
	return nil
}
